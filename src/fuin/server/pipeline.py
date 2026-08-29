"""Server-side packer pipeline.

The single boundary between the FastAPI service and the core packer: nothing
under :mod:`fuin.server` imports :mod:`fuin.packer`, :mod:`fuin.analyze` or
:mod:`fuin.apk_info` directly. Writes the packed APK to the configured
packed-APK directory keyed by SHA-256.
"""

import contextlib
import dataclasses
import logging
import os
import uuid
from collections.abc import Callable

from fuin.apk import get_apk_info
from fuin.contract import PRIMARY_DEX
from fuin.packer import PackOptions, PackResult, pack_apk
from fuin.reporting import analyze_targets as _analyze_targets
from fuin.reporting import generate_report
from fuin.server.config import get_server_settings

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int], None]

__all__ = [
    "PackOptions",
    "PackedOutput",
    "ProgressCallback",
    "analyze_apk",
    "analyze_targets",
    "run_pipeline",
]


@dataclasses.dataclass(frozen=True)
class PackedOutput:
    """What a completed pipeline run produced."""

    path: str
    sha256: str
    report: dict


def analyze_apk(apk_path: str) -> dict:
    """APK metadata, plus whether it has a primary DEX to pack."""
    info = get_apk_info(apk_path)
    info.setdefault("has_classes_dex", PRIMARY_DEX in info.get("dex_files", []))
    return info


def analyze_targets(apk_path: str) -> dict:
    """Preview what packing would encrypt."""
    return _analyze_targets(apk_path)


def run_pipeline(
    input_apk_path: str,
    app_class: str | None = None,
    progress: ProgressCallback | None = None,
    options: PackOptions | None = None,
) -> PackedOutput:
    """Pack ``input_apk_path`` and store the output under the packed-APK dir."""
    options = options or PackOptions()
    if app_class is not None:
        options = dataclasses.replace(options, app_class=app_class)

    packed_dir = get_server_settings().packed_apk_dir
    os.makedirs(packed_dir, exist_ok=True)

    # Pack into a per-call temporary name — concurrent jobs would otherwise
    # clobber each other — then rename to the SHA-256-keyed final path.
    tmp_output = os.path.join(packed_dir, f".pending-{uuid.uuid4().hex}.apk")
    try:
        result: PackResult = pack_apk(
            input_apk_path, tmp_output, options=options, progress=progress
        )
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
    return PackedOutput(path=dest, sha256=result.sha256, report=report)
