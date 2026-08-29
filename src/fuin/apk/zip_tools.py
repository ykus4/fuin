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

    Members are read through their ``ZipInfo``, not their name: an archive may
    legitimately hold two entries with the same name, and ``ZipFile.read(name)``
    resolves every one of them to the last.
    """
    for item in zin.infolist():
        if skip is not None and skip(item.filename):
            continue
        if replace is not None and item.filename in replace:
            zout.writestr(item, replace[item.filename])
        else:
            with zin.open(item) as src:
                zout.writestr(item, src.read())


def sha256_file(path: str) -> str:
    """Streaming SHA-256 of a file, as hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
