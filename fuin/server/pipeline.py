"""
Server-side packer pipeline.

Runs: analyze → encrypt DEX(es) → embed key → patch manifest → inject → zipalign → sign
Returns the path of the packed APK.
"""

import hashlib
import io
import logging
import os
import re
import shutil
import tempfile
import zipfile
from collections.abc import Callable

from fuin import config
from fuin.apk import create_debug_keystore, inject_encrypted_dex, sign_apk, zipalign
from fuin.apk_info import get_apk_info
from fuin.crypto import encrypt_dex, generate_key
from fuin.integrity import extract_cert_fingerprint
from fuin.manifest import patch_manifest
from fuin.native_lib import encrypt_native_libs
from fuin.report import generate_report
from fuin.resource_encrypt import encrypt_resources
from fuin.string_encrypt import encrypt_dex_strings
from fuin.stub_dex import get_stub_dex

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]

_EXTRA_DEX_RE = re.compile(r"^classes(\d+)\.dex$")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_apk(apk_path: str) -> dict:
    info = get_apk_info(apk_path)
    # Ensure legacy keys expected by server/main.py are present
    info.setdefault("has_classes_dex", "classes.dex" in info.get("dex_files", []))
    return info


def _pack_extra_dex(apk_path: str, key: bytes) -> bytes | None:
    """Read classes2.dex, classes3.dex, ... encrypt each and bundle into a ZIP blob."""
    extra: dict[str, bytes] = {}
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in sorted(z.namelist()):
            if _EXTRA_DEX_RE.match(name):
                extra[name] = z.read(name)

    if not extra:
        return None

    # Bundle all extra DEX files into an in-memory ZIP, then encrypt the whole blob
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_STORED) as inner_zip:
        for name, data in extra.items():
            inner_zip.writestr(name, data)
    bundle = inner_buf.getvalue()
    return encrypt_dex(bundle, key)


def _build_security_policy() -> bytes | None:
    """Build security_policy.json from environment config."""
    import json

    root_detection = os.environ.get("FUIN_ROOT_DETECTION", "").lower() in ("1", "true", "yes")
    emulator_detection = os.environ.get("FUIN_EMULATOR_DETECTION", "").lower() in (
        "1",
        "true",
        "yes",
    )

    if not root_detection and not emulator_detection:
        return None

    policy = {
        "root_detection": root_detection,
        "emulator_detection": emulator_detection,
    }
    return json.dumps(policy).encode()


def run_pipeline(
    input_apk_path: str,
    app_class: str | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[str, str, dict]:
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

        # Resolve keystore early (needed for cert fingerprint extraction)
        ks_path = config.KEYSTORE_PATH
        alias = config.KEYSTORE_ALIAS
        sp = config.KEYSTORE_STORE_PASS
        kp = config.KEYSTORE_KEY_PASS

        if not ks_path or not sp or not kp:
            log.warning("no keystore configured — using temporary debug keystore")
            ks_path = os.path.join(tmpdir, "debug.keystore")
            ks = create_debug_keystore(ks_path)
            alias, sp, kp = ks["alias"], ks["store_pass"], ks["key_pass"]

        _progress("encrypting_dex", 40)
        with zipfile.ZipFile(input_apk_path, "r") as z:
            if "classes.dex" not in z.namelist():
                raise ValueError("APK does not contain classes.dex")
            dex_data = z.read("classes.dex")

        key = generate_key()

        # String encryption (opt-in via env)
        string_key = None
        if os.environ.get("FUIN_ENCRYPT_STRINGS", "").lower() in ("1", "true", "yes"):
            dex_data, string_key = encrypt_dex_strings(dex_data, key)
            log.info("applied string encryption to classes.dex")

        encrypted = encrypt_dex(dex_data, key)
        # Encrypt any extra DEX files (multidex support)
        encrypted_extra = _pack_extra_dex(input_apk_path, key)
        if encrypted_extra:
            log.info("multidex: packed extra DEX bundle (%d bytes)", len(encrypted_extra))

        _progress("injecting", 60)

        # Anti-tamper: extract cert fingerprint from keystore
        cert_fp = None
        if ks_path and sp:
            try:
                cert_fp = extract_cert_fingerprint(ks_path, sp)
            except Exception as e:
                log.warning("could not extract cert fingerprint: %s", e)

        # Security policy
        security_policy = _build_security_policy()

        # Encrypt native libraries
        native_libs_result = encrypt_native_libs(step1, key)

        # Encrypt resources/assets
        res_result = encrypt_resources(step1, key)

        inject_encrypted_dex(
            step1,
            encrypted,
            key,
            original_class,
            step2,
            stub_dex=stub_dex,
            encrypted_extra_dex=encrypted_extra,
            cert_fingerprint=cert_fp,
            security_policy=security_policy,
            encrypted_libs=native_libs_result.get("encrypted_libs") if native_libs_result else None,
            native_lib_manifest=native_libs_result.get("manifest") if native_libs_result else None,
            encrypted_resources=res_result.get("encrypted_resources") if res_result else None,
            res_map=res_result.get("res_map") if res_result else None,
            strip_patterns=(
                native_libs_result.get("strip_patterns", []) if native_libs_result else []
            )
            + (res_result.get("strip_patterns", []) if res_result else [])
            or None,
            string_key=string_key,
        )

        _progress("aligning", 75)
        zipalign(step2, step3)

        _progress("signing", 85)
        sign_apk(step3, ks_path, alias, sp, kp)

        _progress("saving", 95)
        sig = _sha256_file(step3)
        dest = os.path.join(config.PACKED_APK_DIR, f"{sig[:16]}_packed.apk")
        shutil.copy(step3, dest)

    _progress("reporting", 97)
    report = generate_report(input_apk_path, dest)

    _progress("done", 100)
    log.info("pipeline complete dest=%s", dest)
    return dest, sig, report
