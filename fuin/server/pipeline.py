"""Server-side packer pipeline.

Wraps :mod:`fuin.packer` for the FastAPI server: writes the packed APK to
``config.PACKED_APK_DIR`` keyed by SHA-256, and returns ``(path, sha256, report)``.
"""

import logging
import os
from collections.abc import Callable

from fuin import config
from fuin.apk_info import get_apk_info
from fuin.packer import PackOptions, pack_apk
from fuin.report import generate_report

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]

# Kept for backwards compatibility with prior callers.
PipelineOptions = PackOptions


def analyze_apk(apk_path: str) -> dict:
    info = get_apk_info(apk_path)
    info.setdefault("has_classes_dex", "classes.dex" in info.get("dex_files", []))
    return info


def run_pipeline(
    input_apk_path: str,
    app_class: str | None = None,
    progress: ProgressCallback | None = None,
    options: PackOptions | None = None,
) -> tuple[str, str, dict]:
    """Pack ``input_apk_path`` and store the output under ``PACKED_APK_DIR``.

    Returns ``(packed_apk_path, sha256_hex, report)``.
    """
    options = options or PackOptions()
    if app_class is not None:
        options = PackOptions(
            app_class=app_class,
            encrypt_native=options.encrypt_native,
            encrypt_assets=options.encrypt_assets,
            encrypt_strings=options.encrypt_strings,
            root_detection=options.root_detection,
            emulator_detection=options.emulator_detection,
            exclude_files=options.exclude_files,
            strict_manifest_patch=options.strict_manifest_patch,
            verify_signature=options.verify_signature,
            keystore_path=options.keystore_path,
            keystore_alias=options.keystore_alias,
            keystore_store_pass=options.keystore_store_pass,
            keystore_key_pass=options.keystore_key_pass,
        )

    os.makedirs(config.PACKED_APK_DIR, exist_ok=True)

    # Write to a temporary location keyed off the timestamp of the call's
    # input then rename to the SHA-256-keyed final path.
    tmp_output = os.path.join(config.PACKED_APK_DIR, ".pending.apk")
    result = pack_apk(input_apk_path, tmp_output, options=options, progress=progress)

    dest = os.path.join(config.PACKED_APK_DIR, f"{result.sha256[:16]}_packed.apk")
    os.replace(tmp_output, dest)

    if progress:
        progress("reporting", 97)
    report = generate_report(input_apk_path, dest)
    if progress:
        progress("done", 100)
    log.info("pipeline complete dest=%s", dest)
    return dest, result.sha256, report
