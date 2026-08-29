"""End-to-end packing orchestration shared by the CLI and the server pipeline.

Stages: load_stub → patch_manifest → encrypt_dex → encrypt_libs/assets →
inject → zipalign → sign → (verify) → done.
"""

import io
import json
import logging
import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field

from fuin import config
from fuin.apk import (
    InjectedAssets,
    get_stub_dex,
    inject_encrypted_dex,
    keystore,
    patch_manifest,
    sha256_file,
    sign_apk,
    verify_apk_signature,
    zipalign,
)
from fuin.contract import EXTRA_DEX_RE, PRIMARY_DEX
from fuin.encryption import (
    encrypt_blob,
    encrypt_dex_strings,
    encrypt_native_libs,
    encrypt_resources,
    generate_key,
)

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]


@dataclass(frozen=True)
class PackOptions:
    """User-controllable options for a single pack invocation."""

    app_class: str | None = None
    encrypt_native: bool = True
    encrypt_assets: bool = True

    # Tri-state: ``None`` defers to the corresponding environment setting,
    # an explicit ``True``/``False`` always wins over it.
    encrypt_strings: bool | None = None
    root_detection: bool | None = None
    emulator_detection: bool | None = None
    strict_manifest_patch: bool | None = None
    verify_signature: bool | None = None

    exclude_files: tuple[str, ...] = field(default_factory=tuple)

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
        extra = {name: z.read(name) for name in sorted(z.namelist()) if EXTRA_DEX_RE.match(name)}
    if not extra:
        return None

    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_STORED) as inner_zip:
        for name, data in extra.items():
            inner_zip.writestr(name, data)
    return encrypt_blob(inner_buf.getvalue(), key)


def _resolve(explicit: bool | None, fallback: bool) -> bool:
    """Return ``explicit`` unless it was left unset, in which case ``fallback``."""
    return fallback if explicit is None else explicit


def _keystore_was_configured(options: PackOptions, settings: config.Settings) -> bool:
    """Whether the caller supplied a keystore, rather than getting the debug one."""
    return bool(options.keystore_path or settings.keystore_path)


def _cert_fingerprint(ks: keystore.Keystore, *, configured: bool) -> bytes | None:
    """Digest of the signing certificate, for the stub's anti-repackaging check.

    A failure here silently disables that check, so it is only tolerated for
    the throwaway debug keystore. If the user pointed fuin at a real keystore
    and it cannot be read, that is a wrong password or a wrong path — failing
    the pack is better than shipping unprotected.
    """
    try:
        return keystore.extract_cert_fingerprint(ks.path, ks.store_pass)
    except (ValueError, OSError) as exc:
        if configured:
            raise ValueError(
                f"could not read the signing certificate from {ks.path}: {exc}"
            ) from exc
        log.warning("could not extract cert fingerprint: %s", exc)
        return None


def _build_security_policy(options: PackOptions, settings: config.Settings) -> bytes | None:
    root = _resolve(options.root_detection, settings.root_detection)
    emu = _resolve(options.emulator_detection, settings.emulator_detection)
    if not root and not emu:
        return None
    return json.dumps({"root_detection": root, "emulator_detection": emu}).encode()


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
    settings = config.get_settings()

    def _progress(step: str, pct: int) -> None:
        log.info("%s (%d%%)", step, pct)
        if progress:
            progress(step, pct)

    _progress("loading_stub", 5)
    stub_dex = get_stub_dex()
    log.debug("stub.dex size: %d bytes", len(stub_dex))

    with zipfile.ZipFile(input_apk, "r") as z:
        if PRIMARY_DEX not in z.namelist():
            raise ValueError(f"APK does not contain {PRIMARY_DEX}")

    with tempfile.TemporaryDirectory() as tmpdir:
        step1 = os.path.join(tmpdir, "step1_manifest.apk")
        step2 = os.path.join(tmpdir, "step2_injected.apk")
        step3 = os.path.join(tmpdir, "step3_aligned.apk")

        _progress("patching_manifest", 20)
        found_class = patch_manifest(input_apk, step1, options.app_class)
        strict = _resolve(options.strict_manifest_patch, settings.strict_manifest_patch)
        if strict and not found_class:
            raise ValueError(
                "AndroidManifest.xml could not be patched with StubApplication. "
                "Provide app_class explicitly or disable strict_manifest_patch."
            )

        ks = keystore.resolve(options, settings, tmpdir)

        _progress("encrypting_dex", 40)
        with zipfile.ZipFile(input_apk, "r") as z:
            dex_data = z.read(PRIMARY_DEX)

        key = generate_key()
        string_key = None
        if _resolve(options.encrypt_strings, settings.encrypt_strings):
            dex_data, string_key = encrypt_dex_strings(dex_data, key)
            log.info("applied string encryption to classes.dex")

        encrypted = encrypt_blob(dex_data, key)
        encrypted_extra = _pack_extra_dex(input_apk, key)
        if encrypted_extra:
            log.info("multidex: packed extra DEX bundle (%d bytes)", len(encrypted_extra))

        _progress("injecting", 60)

        cert_fp = _cert_fingerprint(ks, configured=_keystore_was_configured(options, settings))
        security_policy = _build_security_policy(options, settings)

        exclude = set(options.exclude_files)
        native = (
            encrypt_native_libs(step1, key, exclude_files=exclude)
            if options.encrypt_native
            else None
        )
        resources = (
            encrypt_resources(step1, key, exclude_files=exclude) if options.encrypt_assets else None
        )

        assets = InjectedAssets(
            stub_dex=stub_dex,
            encrypted_extra_dex=encrypted_extra,
            cert_fingerprint=cert_fp,
            security_policy=security_policy,
            string_key=string_key,
            encrypted_libs=native.blobs if native else {},
            native_lib_manifest=native.index if native else None,
            encrypted_resources=resources.blobs if resources else {},
            res_map=resources.index if resources else None,
            strip_names=(native.strip_names if native else frozenset())
            | (resources.strip_names if resources else frozenset()),
        )

        inject_encrypted_dex(step1, encrypted, key, found_class or "", step2, assets)

        _progress("aligning", 75)
        zipalign(step2, step3)

        _progress("signing", 85)
        sign_apk(step3, ks.path, ks.alias, ks.store_pass, ks.key_pass)

        if _resolve(options.verify_signature, settings.verify_signature):
            if not verify_apk_signature(step3):
                raise RuntimeError(
                    "verify_signature is enabled but apksigner was not found. "
                    "Install Android build-tools or disable verification."
                )
            log.info("verified APK signature with apksigner")

        shutil.copy(step3, output_apk)

    sha = sha256_file(output_apk)
    log.info("done: %s", output_apk)
    return PackResult(output_path=output_apk, sha256=sha, original_app_class=found_class or "")
