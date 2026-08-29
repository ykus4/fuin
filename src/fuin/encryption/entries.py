"""Lifting APK entries out into encrypted assets.

Native libraries and user assets are the same operation with a different
selector and a different index format: read the matching entries, encrypt each
one, and tell the repacker which originals to drop. Keeping that shape here
stops the two from drifting — they already had, over whether a directory entry
counts as a file and over whether ``exclude_files`` was honoured.
"""

import zipfile
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EncryptedEntries:
    """Entries that have been encrypted into assets.

    ``strip_names`` holds the *exact* original entry names to remove. It used
    to be a list of regexes, which meant the repacker ran every pattern against
    every entry, and let ``encrypt_native_libs`` return one blanket
    ``^lib/.*\\.so$`` that also deleted the libraries it had been told to
    exclude.
    """

    blobs: dict[str, bytes]
    index: bytes
    strip_names: frozenset[str]


def read_matching_entries(
    apk_path: str,
    select: Callable[[str], bool],
    exclude_files: set[str],
) -> dict[str, bytes]:
    """Read every entry ``select`` accepts and ``exclude_files`` does not veto.

    Members are read through their ``ZipInfo`` so duplicate names do not all
    collapse onto the last one.
    """
    found: dict[str, bytes] = {}
    with zipfile.ZipFile(apk_path, "r") as z:
        for info in z.infolist():
            name = info.filename
            if name in exclude_files or name in found or not select(name):
                continue
            with z.open(info) as src:
                found[name] = src.read()
    return found
