"""End-to-end packing orchestration shared by the CLI and the server pipeline.

Stages: load_stub → patch_manifest → encrypt_dex → encrypt_libs/assets →
inject → zipalign → sign → (verify) → done.
"""

import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field

from fuin import config
from fuin._utils import parse_env_bool
from fuin.apk import create_debug_keystore, inject_encrypted_dex
from fuin.crypto import encrypt_blob, generate_key
from fuin.integrity import extract_cert_fingerprint
from fuin.manifest import patch_manifest
from fuin.native_lib import encrypt_native_libs
from fuin.resource_encrypt import encrypt_resources
from fuin.signing import sign_apk, verify_apk_signature
from fuin.string_encrypt import encrypt_dex_strings
from fuin.stub_dex import get_stub_dex
from fuin.zipalign import zipalign

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]

_EXTRA_DEX_RE = re.compile(r"^classes(\d+)\.dex$")


@dataclass(frozen=True)
class PackOptions:
    """User-controllable options for a single pack invocation."""

    app_class: str | None = None
    encrypt_native: bool = True
    encrypt_assets: bool = True
    encrypt_strings: bool = False
    root_detection: bool = False
    emulator_detection: bool = False
    exclude_files: tuple[str, ...] = field(default_factory=tuple)
    strict_manifest_patch: bool | None = None
    verify_signature: bool | None = None

    # Optional keystore overrides (CLI uses these; server inherits from config)
    keystore_path: str | None = None
    keystore_alias: str | None = None
    keystore_store_pass: str | None = None
    keystore_key_pass: str | None = None


@dataclass(frozen=True)
class PackResult:
    output_path: str
    sha256: str
    original_app_class: str


def _pack_extra_dex(apk_path: str, key: bytes) -> bytes | None:
    """Bundle classes2.dex, classes3.dex, ... into a ZIP, then encrypt as one blob."""
    with zipfile.ZipFile(apk_path, "r") as z:
        extra = {name: z.read(name) for name in sorted(z.namelist()) if _EXTRA_DEX_RE.match(name)}
    if not extra:
        return None

    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_STORED) as inner_zip:
        for name, data in extra.items():
            inner_zip.writestr(name, data)
    return encrypt_blob(inner_buf.getvalue(), key)


def _build_security_policy(options: PackOptions) -> bytes | None:
    root = options.root_detection or parse_env_bool(os.environ.get("FUIN_ROOT_DETECTION"))
    emu = options.emulator_detection or parse_env_bool(os.environ.get("FUIN_EMULATOR_DETECTION"))
    if not root and not emu:
        return None
    return json.dumps({"root_detection": root, "emulator_detection": emu}).encode()


def _resolve_keystore(options: PackOptions, tmpdir: str) -> tuple[str, str, str, str]:
    """Return (path, alias, store_pass, key_pass). Falls back to a debug keystore."""
    ks_path = options.keystore_path or config.KEYSTORE_PATH
    alias = options.keystore_alias or config.KEYSTORE_ALIAS
    sp = options.keystore_store_pass or config.KEYSTORE_STORE_PASS
    kp = options.keystore_key_pass or config.KEYSTORE_KEY_PASS

    if not ks_path or not sp or not kp:
        log.warning("no keystore configured — using temporary debug keystore")
        ks = create_debug_keystore(os.path.join(tmpdir, "debug.keystore"))
        return ks["keystore"], ks["alias"], ks["store_pass"], ks["key_pass"]
    return ks_path, alias, sp, kp


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_apk(
    input_apk: str,
    output_apk: str,
    options: PackOptions | None = None,
    progress: ProgressCallback | None = None,
) -> PackResult:
    """Pack an APK end-to-end.

    The output is written to ``output_apk``. Progress is reported as
    ``(step_name, percent)`` if a callback is provided.
    """
    options = options or PackOptions()

    def _progress(step: str, pct: int) -> None:
        log.info("%s (%d%%)", step, pct)
        if progress:
            progress(step, pct)

    _progress("loading_stub", 5)
    stub_dex = get_stub_dex()
    log.debug("stub.dex size: %d bytes", len(stub_dex))

    with zipfile.ZipFile(input_apk, "r") as z:
        if "classes.dex" not in z.namelist():
            raise ValueError("APK does not contain classes.dex")

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest.apk")
        step2 = os.path.join(tmpdir, "step2_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        _progress("patching_manifest", 20)
        found_class = patch_manifest(input_apk, step1, options.app_class)
        strict = (
            config.STRICT_MANIFEST_PATCH
            if options.strict_manifest_patch is None
            else options.strict_manifest_patch
        )
        if strict and not found_class:
            raise ValueError(
                "AndroidManifest.xml could not be patched with StubApplication. "
                "Provide app_class explicitly or disable strict_manifest_patch."
            )

        ks_path, alias, sp, kp = _resolve_keystore(options, tmpdir)

        _progress("encrypting_dex", 40)
        with zipfile.ZipFile(input_apk, "r") as z:
            dex_data = z.read("classes.dex")

        key = generate_key()
        string_key = None
        if options.encrypt_strings or parse_env_bool(os.environ.get("FUIN_ENCRYPT_STRINGS")):
            dex_data, string_key = encrypt_dex_strings(dex_data, key)
            log.info("applied string encryption to classes.dex")

        encrypted = encrypt_blob(dex_data, key)
        encrypted_extra = _pack_extra_dex(input_apk, key)
        if encrypted_extra:
            log.info("multidex: packed extra DEX bundle (%d bytes)", len(encrypted_extra))

        _progress("injecting", 60)

        cert_fp = None
        try:
            cert_fp = extract_cert_fingerprint(ks_path, sp)
        except Exception as e:
            log.warning("could not extract cert fingerprint: %s", e)

        security_policy = _build_security_policy(options)

        exclude = set(options.exclude_files)
        native_result = (
            encrypt_native_libs(step1, key, exclude_files=exclude)
            if options.encrypt_native
            else None
        )
        res_result = (
            encrypt_resources(step1, key, exclude_files=exclude) if options.encrypt_assets else None
        )

        strip = (native_result.get("strip_patterns", []) if native_result else []) + (
            res_result.get("strip_patterns", []) if res_result else []
        )

        inject_encrypted_dex(
            step1,
            encrypted,
            key,
            found_class or "",
            step2,
            stub_dex=stub_dex,
            encrypted_extra_dex=encrypted_extra,
            cert_fingerprint=cert_fp,
            security_policy=security_policy,
            encrypted_libs=native_result.get("encrypted_libs") if native_result else None,
            native_lib_manifest=native_result.get("manifest") if native_result else None,
            encrypted_resources=res_result.get("encrypted_resources") if res_result else None,
            res_map=res_result.get("res_map") if res_result else None,
            strip_patterns=strip or None,
            string_key=string_key,
        )

        _progress("aligning", 75)
        zipalign(step2, step3)

        _progress("signing", 85)
        sign_apk(step3, ks_path, alias, sp, kp)

        verify = (
            config.VERIFY_SIGNATURE
            if options.verify_signature is None
            else options.verify_signature
        )
        if verify:
            if not verify_apk_signature(step3):
                raise RuntimeError(
                    "verify_signature is enabled but apksigner was not found. "
                    "Install Android build-tools or disable verification."
                )
            log.info("verified APK signature with apksigner")

        shutil.copy(step3, output_apk)

    sha = _sha256_file(output_apk)
    log.info("done: %s", output_apk)
    return PackResult(output_path=output_apk, sha256=sha, original_app_class=found_class or "")
