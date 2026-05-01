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
from collections.abc import Callable

from fuin import config
from fuin.apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from fuin.cli import get_package_name
from fuin.crypto import encrypt_dex, generate_key
from fuin.manifest import patch_manifest
from fuin.stub_dex import get_stub_dex

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]


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

    return {
        "package_name": get_package_name(apk_path),
        "has_classes_dex": has_dex,
        "file_size_bytes": os.path.getsize(apk_path),
        "entry_count": len(names),
    }


def run_pipeline(
    input_apk_path: str,
    app_class: str | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[str, str]:
    """
    Returns:
        (packed_apk_path, apk_sha256_hex)

    progress(step_name, percent) is called at each stage if provided.
    """

    def _progress(step: str, pct: int) -> None:
        log.info("%s (%d%%)", step, pct)
        if progress:
            progress(step, pct)

    os.makedirs(config.PACKED_APK_DIR, exist_ok=True)

    _progress("loading_stub", 5)
    stub_dex = get_stub_dex()

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest.apk")
        step2 = os.path.join(tmpdir, "step2_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        _progress("patching_manifest", 20)
        original_class = patch_manifest(input_apk_path, step1, app_class)

        _progress("encrypting_dex", 40)
        with zipfile.ZipFile(input_apk_path, "r") as z:
            if "classes.dex" not in z.namelist():
                raise ValueError("APK does not contain classes.dex")
            dex_data = z.read("classes.dex")

        key = generate_key()
        encrypted = encrypt_dex(dex_data, key)

        _progress("injecting", 60)
        inject_encrypted_dex(step1, encrypted, key, original_class, step2, stub_dex=stub_dex)

        _progress("aligning", 75)
        zipalign(step2, step3)

        _progress("signing", 85)
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

        _progress("saving", 95)
        sig = _sha256_file(step3)
        dest = os.path.join(config.PACKED_APK_DIR, f"{sig[:16]}_packed.apk")
        shutil.copy(step3, dest)

    _progress("done", 100)
    log.info("pipeline complete dest=%s", dest)
    return dest, sig
