"""
fuin packer — CLI entry point.

Usage:
    fuin-pack pack <input.apk> <output.apk> [options]
"""

import argparse
import json
import logging
import os
import shutil
import tempfile
import zipfile

from fuin import config
from fuin.apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from fuin.crypto import encrypt_dex, generate_key
from fuin.integrity import extract_cert_fingerprint
from fuin.manifest import patch_manifest
from fuin.native_lib import encrypt_native_libs
from fuin.report import format_report, generate_report
from fuin.resource_encrypt import encrypt_resources
from fuin.server.pipeline import _pack_extra_dex
from fuin.string_encrypt import encrypt_dex_strings
from fuin.stub_dex import get_stub_dex

log = logging.getLogger(__name__)


def get_package_name(apk_path: str) -> str:
    with zipfile.ZipFile(apk_path, "r") as z:
        data = z.read("AndroidManifest.xml")
    idx = data.find(b"package")
    if idx == -1:
        return "unknown"
    chunk = data[idx : idx + 256]
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = chunk.decode(encoding, errors="ignore")
            for p in text.split():
                if "." in p and p.replace(".", "").replace("_", "").isalnum():
                    return p
        except Exception:
            pass
    return "unknown"


def pack(args: argparse.Namespace) -> None:
    input_apk: str = args.input
    output_apk: str = args.output
    original_app: str = args.app_class or ""

    log.info("packing %s", input_apk)

    stub_dex = get_stub_dex()
    log.debug("stub.dex size: %d bytes", len(stub_dex))

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest.apk")
        step2 = os.path.join(tmpdir, "step2_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        log.info("patching AndroidManifest.xml")
        found_class = patch_manifest(input_apk, step1, original_app or None)
        if found_class:
            log.info("original Application class: %s", found_class)
        else:
            found_class = ""

        # Resolve keystore early (needed for cert fingerprint)
        ks_path = args.keystore or config.KEYSTORE_PATH
        alias = args.key_alias or config.KEYSTORE_ALIAS
        sp = args.store_pass or config.KEYSTORE_STORE_PASS
        kp = args.key_pass or config.KEYSTORE_KEY_PASS

        if not ks_path or not sp or not kp:
            log.warning("no keystore configured — using temporary debug keystore")
            ks_file = os.path.join(tmpdir, "debug.keystore")
            ks = create_debug_keystore(ks_file)
            ks_path, alias, sp, kp = ks["keystore"], ks["alias"], ks["store_pass"], ks["key_pass"]

        log.info("encrypting classes.dex")
        with zipfile.ZipFile(input_apk, "r") as z:
            if "classes.dex" not in z.namelist():
                raise FileNotFoundError("classes.dex not found in APK")
            dex_data = z.read("classes.dex")

        key = generate_key()

        # String encryption (XOR obfuscation on DEX string data)
        string_key = None
        if args.encrypt_strings:
            dex_data, string_key = encrypt_dex_strings(dex_data, key)
            log.info("applied string encryption to classes.dex")

        encrypted = encrypt_dex(dex_data, key)
        encrypted_extra = _pack_extra_dex(input_apk, key)
        if encrypted_extra:
            log.info("multidex: packed extra DEX bundle (%d bytes)", len(encrypted_extra))

        # Anti-tamper: cert fingerprint
        cert_fp = None
        try:
            cert_fp = extract_cert_fingerprint(ks_path, sp)
            log.info("extracted cert fingerprint for anti-tamper")
        except Exception as e:
            log.warning("could not extract cert fingerprint: %s", e)

        # Security policy
        security_policy = None
        if args.root_detection or args.emulator_detection:
            policy = {
                "root_detection": args.root_detection,
                "emulator_detection": args.emulator_detection,
            }
            security_policy = json.dumps(policy).encode()
            log.info("security policy: %s", policy)

        # Native library encryption
        native_libs_result = None
        if not args.no_native_encrypt:
            native_libs_result = encrypt_native_libs(step1, key)
            if native_libs_result:
                log.info("encrypted %d native libraries", len(native_libs_result["encrypted_libs"]))

        # Resource/asset encryption
        res_result = None
        if not args.no_resource_encrypt:
            res_result = encrypt_resources(step1, key)
            if res_result:
                log.info("encrypted %d assets", len(res_result["encrypted_resources"]))

        # Build strip patterns
        strip = (native_libs_result.get("strip_patterns", []) if native_libs_result else []) + (
            res_result.get("strip_patterns", []) if res_result else []
        )

        inject_encrypted_dex(
            step1,
            encrypted,
            key,
            found_class,
            step2,
            stub_dex=stub_dex,
            encrypted_extra_dex=encrypted_extra,
            cert_fingerprint=cert_fp,
            security_policy=security_policy,
            encrypted_libs=native_libs_result.get("encrypted_libs") if native_libs_result else None,
            native_lib_manifest=native_libs_result.get("manifest") if native_libs_result else None,
            encrypted_resources=res_result.get("encrypted_resources") if res_result else None,
            res_map=res_result.get("res_map") if res_result else None,
            strip_patterns=strip or None,
            string_key=string_key,
        )

        log.info("running zipalign")
        zipalign(step2, step3)

        log.info("signing APK")
        sign_apk(step3, ks_path, alias, sp, kp)
        shutil.copy(step3, output_apk)

    log.info("done: %s", output_apk)

    if args.report or args.report_json:
        report = generate_report(input_apk, output_apk)
        if args.report_json:
            print(json.dumps(report, indent=2))
        else:
            print(format_report(report))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuin", description="Android DEX Packer")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    pack_p = sub.add_parser("pack", help="Pack and encrypt an APK")
    pack_p.add_argument("input", help="Input APK path")
    pack_p.add_argument("output", help="Output (protected) APK path")
    pack_p.add_argument(
        "--app-class", help="Original Application class name (optional, auto-detected)"
    )
    pack_p.add_argument("--keystore", help="Keystore path (overrides FUIN_KEYSTORE_PATH)")
    pack_p.add_argument("--key-alias", help="Key alias (overrides FUIN_KEYSTORE_ALIAS)")
    pack_p.add_argument(
        "--store-pass", help="Keystore password (overrides FUIN_KEYSTORE_STORE_PASS)"
    )
    pack_p.add_argument("--key-pass", help="Key password (overrides FUIN_KEYSTORE_KEY_PASS)")
    pack_p.add_argument("--report", action="store_true", help="Print pack diff report")
    pack_p.add_argument("--report-json", action="store_true", help="Print pack diff report as JSON")
    pack_p.add_argument(
        "--root-detection", action="store_true", help="Enable root detection at runtime"
    )
    pack_p.add_argument(
        "--emulator-detection", action="store_true", help="Enable emulator detection at runtime"
    )
    pack_p.add_argument(
        "--no-native-encrypt", action="store_true", help="Disable native library (.so) encryption"
    )
    pack_p.add_argument(
        "--no-resource-encrypt", action="store_true", help="Disable asset/resource encryption"
    )
    pack_p.add_argument(
        "--encrypt-strings", action="store_true", help="Enable DEX string obfuscation"
    )

    # --- analyze subcommand ---
    analyze_p = sub.add_parser("analyze", help="Preview what will be encrypted in an APK")
    analyze_p.add_argument("input", help="Input APK path")
    analyze_p.add_argument("--json", action="store_true", help="Output as JSON")

    return parser


def analyze(args: argparse.Namespace) -> None:
    """Preview encryption targets without actually packing."""
    from fuin.analyze import analyze_targets

    result = analyze_targets(args.input)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_analysis(result)


def _print_analysis(result: dict) -> None:
    """Pretty-print analysis results."""
    print("=== Fuin Encryption Analysis ===")
    print()

    # DEX files
    dex = result["dex"]
    print(f"DEX files ({len(dex['files'])} total, {_fmt_size(dex['total_size'])}):")
    for f in dex["files"]:
        print(f"  ✓ {f['name']}  ({_fmt_size(f['size'])})")
    print()

    # Native libraries
    native = result["native_libs"]
    if native["files"]:
        print(
            f"Native libraries ({len(native['files'])} total, {_fmt_size(native['total_size'])}):"
        )
        for f in native["files"]:
            print(f"  ✓ {f['name']}  ({_fmt_size(f['size'])})")
    else:
        print("Native libraries: none found")
    print()

    # Assets
    assets = result["assets"]
    if assets["files"]:
        print(f"User assets ({len(assets['files'])} total, {_fmt_size(assets['total_size'])}):")
        for f in assets["files"]:
            print(f"  ✓ {f['name']}  ({_fmt_size(f['size'])})")
    else:
        print("User assets: none found")
    print()

    # Summary
    summary = result["summary"]
    print("--- Summary ---")
    print(f"  Total encryptable files: {summary['total_files']}")
    print(f"  Total encryptable size:  {_fmt_size(summary['total_size'])}")
    print(f"  APK total size:          {_fmt_size(summary['apk_size'])}")
    print(f"  Protection coverage:     {summary['coverage_percent']:.1f}% of APK content")


def _fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "pack":
        pack(args)
    elif args.command == "analyze":
        analyze(args)


if __name__ == "__main__":
    main()
