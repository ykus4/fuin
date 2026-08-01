"""Low-level ZIP helpers shared by the repack and signing steps."""

import hashlib
import zipfile
from collections.abc import Callable


def copy_zip_entries(
    zin: zipfile.ZipFile,
    zout: zipfile.ZipFile,
    *,
    skip: Callable[[str], bool] | None = None,
    replace: dict[str, bytes] | None = None,
) -> None:
    """Copy every entry from ``zin`` to ``zout``, dropping those ``skip`` selects.

    Entries named in ``replace`` are written with the supplied contents instead
    of the original, keeping their position in the archive. Entry metadata is
    preserved by passing the original ``ZipInfo`` through.
    """
    for item in zin.infolist():
        if skip is not None and skip(item.filename):
            continue
        if replace is not None and item.filename in replace:
            zout.writestr(item, replace[item.filename])
        else:
            zout.writestr(item, zin.read(item.filename))


def sha256_file(path: str) -> str:
    """Streaming SHA-256 of a file, as hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
