"""
Server-side packer pipeline.

Runs: analyze → encrypt DEX → embed key → patch manifest → inject → zipalign → sign
Returns the path of the packed APK.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import zipfile

import config
from packer.apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from packer.crypto import encrypt_dex, generate_key
from packer.manifest import patch_manifest
from packer.stub_dex import get_stub_dex

log = logging.getLogger(__name__)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_apk(apk_path: str) -> dict:
    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()
        has_dex = "classes.dex" in names

    from packer.main import get_package_name

    return {
        "package_name": get_package_name(apk_path),
        "has_classes_dex": has_dex,
        "file_size_bytes": os.path.getsize(apk_path),
        "entry_count": len(names),
    }


def run_pipeline(
    input_apk_path: str,
    app_class: str | None = None,
) -> tuple[str, str]:
    """
    Returns:
        (packed_apk_path, apk_sha256_hex)
    """
    os.makedirs(config.PACKED_APK_DIR, exist_ok=True)

    stub_dex = get_stub_dex()

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest.apk")
        step2 = os.path.join(tmpdir, "step2_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        log.info("patching manifest")
        original_class = patch_manifest(input_apk_path, step1, app_class)

        log.info("encrypting DEX")
        with zipfile.ZipFile(input_apk_path, "r") as z:
            if "classes.dex" not in z.namelist():
                raise ValueError("APK does not contain classes.dex")
            dex_data = z.read("classes.dex")

        key = generate_key()
        encrypted = encrypt_dex(dex_data, key)
        inject_encrypted_dex(step1, encrypted, key, original_class, step2, stub_dex=stub_dex)

        log.info("aligning and signing")
        zipalign(step2, step3)

        ks_path = config.KEYSTORE_PATH
        alias = config.KEYSTORE_ALIAS
        sp = config.KEYSTORE_STORE_PASS
        kp = config.KEYSTORE_KEY_PASS

        if not ks_path or not sp or not kp:
            log.warning("no keystore configured — using temporary debug keystore")
            ks_path = os.path.join(tmpdir, "debug.keystore")
            ks = create_debug_keystore(ks_path)
            alias, sp, kp = ks["alias"], ks["store_pass"], ks["key_pass"]

        sign_apk(step3, ks_path, alias, sp, kp)

        sig = _sha256_file(step3)
        dest = os.path.join(config.PACKED_APK_DIR, f"{sig[:16]}_packed.apk")
        shutil.copy(step3, dest)

    log.info("pipeline complete dest=%s", dest)
    return dest, sig
