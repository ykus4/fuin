"""Server-side packer pipeline.

Wraps :mod:`fuin.packer` for the FastAPI server: writes the packed APK to
the configured packed-APK directory keyed by SHA-256, and returns
``(path, sha256, report)``.
"""

import contextlib
import dataclasses
import logging
import os
import uuid
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
        options = dataclasses.replace(options, app_class=app_class)

    packed_dir = config.get_settings().packed_apk_dir
    os.makedirs(packed_dir, exist_ok=True)

    # Pack into a per-call temporary name — concurrent jobs would otherwise
    # clobber each other — then rename to the SHA-256-keyed final path.
    tmp_output = os.path.join(packed_dir, f".pending-{uuid.uuid4().hex}.apk")
    try:
        result = pack_apk(input_apk_path, tmp_output, options=options, progress=progress)
        dest = os.path.join(packed_dir, f"{result.sha256[:16]}_packed.apk")
        os.replace(tmp_output, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_output)
        raise

    if progress:
        progress("reporting", 97)
    report = generate_report(input_apk_path, dest)
    if progress:
        progress("done", 100)
    log.info("pipeline complete dest=%s", dest)
    return dest, result.sha256, report
