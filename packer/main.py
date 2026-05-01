"""
fuin packer — CLI entry point.

Usage:
    fuin-pack pack <input.apk> <output.apk> [options]
"""

import argparse
import hashlib
import logging
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

# Allow importing root-level config when running as a script
sys.path.insert(0, str(Path(__file__).parent.parent))
from apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from crypto import encrypt_dex, generate_key
from manifest import patch_manifest
from server_client import KeyServerClient
from stub_dex import get_stub_dex

import config

log = logging.getLogger(__name__)


def get_apk_signature(apk_path: str) -> str:
    with open(apk_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


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

    log.info("loading stub DEX")
    stub_dex = get_stub_dex()
    log.debug("stub.dex size: %d bytes", len(stub_dex))

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest_patched.apk")
        step2 = os.path.join(tmpdir, "step2_dex_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        log.info("patching AndroidManifest.xml")
        found_class = patch_manifest(input_apk, step1, original_app or None)
        if found_class:
            log.info("original Application class: %s", found_class)
        else:
            log.info("no existing Application class found; stub will be injected")
            found_class = ""

        log.info("encrypting classes.dex")
        with zipfile.ZipFile(input_apk, "r") as z:
            if "classes.dex" not in z.namelist():
                raise FileNotFoundError("classes.dex not found in APK")
            dex_data = z.read("classes.dex")

        key = generate_key()
        encrypted = encrypt_dex(dex_data, key)
        log.debug("AES key (hex): %s", key.hex())

        inject_encrypted_dex(step1, encrypted, found_class, step2, stub_dex=stub_dex)

        log.info("running zipalign")
        zipalign(step2, step3)

        log.info("signing APK")
        # Prefer CLI args → root config → debug keystore
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
    log.info("AES key (store securely): %s", key.hex())

    server_url = args.server_url or config.SERVER_URL
    api_key = args.api_key or config.ADMIN_API_KEY
    if server_url:
        log.info("registering with key server")
        client = KeyServerClient(server_url, api_key or "")
        pkg = get_package_name(output_apk)
        sig = get_apk_signature(output_apk)
        app_id = client.register_apk(pkg, key, sig)
        log.info("registered — app_id: %s", app_id)


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
    pack_p.add_argument("--server-url", help="Key server base URL (overrides FUIN_SERVER_URL)")
    pack_p.add_argument("--api-key", help="Key server API key (overrides FUIN_API_KEY)")

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
