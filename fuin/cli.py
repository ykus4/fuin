"""
fuin packer — CLI entry point.

Usage:
    fuin-pack pack <input.apk> <output.apk> [options]
"""

import argparse
import logging
import os
import shutil
import tempfile
import zipfile

from fuin import config
from fuin.apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from fuin.crypto import encrypt_dex, generate_key
from fuin.manifest import patch_manifest
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

        log.info("encrypting classes.dex")
        with zipfile.ZipFile(input_apk, "r") as z:
            if "classes.dex" not in z.namelist():
                raise FileNotFoundError("classes.dex not found in APK")
            dex_data = z.read("classes.dex")

        key = generate_key()
        encrypted = encrypt_dex(dex_data, key)
        inject_encrypted_dex(step1, encrypted, key, found_class, step2, stub_dex=stub_dex)

        log.info("running zipalign")
        zipalign(step2, step3)

        log.info("signing APK")
        ks_path = args.keystore or config.KEYSTORE_PATH
        alias = args.key_alias or config.KEYSTORE_ALIAS
        sp = args.store_pass or config.KEYSTORE_STORE_PASS
        kp = args.key_pass or config.KEYSTORE_KEY_PASS

        if not ks_path or not sp or not kp:
            log.warning("no keystore configured — using temporary debug keystore")
            ks_file = os.path.join(tmpdir, "debug.keystore")
            ks = create_debug_keystore(ks_file)
            ks_path, alias, sp, kp = ks["keystore"], ks["alias"], ks["store_pass"], ks["key_pass"]

        sign_apk(step3, ks_path, alias, sp, kp)
        shutil.copy(step3, output_apk)

    log.info("done: %s", output_apk)


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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "pack":
        pack(args)


if __name__ == "__main__":
    main()
