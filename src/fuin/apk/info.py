"""APK metadata: the manifest, plus what only the ZIP can tell you.

The manifest parsing itself is byte-level and lives in :mod:`fuin.axml.info`.
This is the wrapper that opens the archive — which is why it sits here, on the
ZIP-owning side of the `apk/` → `axml/` line.
"""

import logging
import os
import zipfile

from fuin.axml.constants import MANIFEST_NAME
from fuin.axml.info import empty_manifest_info, parse_manifest
from fuin.axml.reader import fallback_package_name
from fuin.contract import DEX_NAME_RE

log = logging.getLogger(__name__)


def get_apk_info(apk_path: str) -> dict:
    """Return a metadata dict for an APK.

    Always returns the same keys. An unreadable archive reports the failure in
    ``error`` and leaves the rest at their empty values, rather than returning
    a shorter dict that makes every caller's key access a KeyError on exactly
    the malformed-input path.
    """
    info = empty_manifest_info()
    info["error"] = None

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            axml = z.read(MANIFEST_NAME) if MANIFEST_NAME in names else b""
    except (OSError, zipfile.BadZipFile) as exc:
        log.warning("failed to read APK %s: %s", apk_path, exc)
        info["package_name"] = "unknown"
        info["error"] = str(exc)
        names, axml = [], b""
    else:
        info.update(parse_manifest(axml))

    info["dex_files"] = sorted(n for n in names if DEX_NAME_RE.match(n))
    info["dex_count"] = len(info["dex_files"])
    info["entry_count"] = len(names)
    info["file_size_bytes"] = os.path.getsize(apk_path) if os.path.exists(apk_path) else 0

    if not info["package_name"]:
        info["package_name"] = fallback_package_name(axml) if axml else "unknown"

    return info
