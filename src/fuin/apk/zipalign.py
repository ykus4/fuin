"""ZIP entry alignment for APKs.

Android mmaps STORED entries straight out of the APK, so their file data has to
start on an aligned boundary — 4 bytes in general, and a whole page for `.so`
files that are loaded without being extracted.

Uses the Android SDK `zipalign` binary when available and falls back to a
pure-Python implementation, so fuin works without the Android SDK installed.
"""

import logging
import os
import shutil
import struct
import tempfile
from pathlib import Path

from fuin.apk.constants import APK_SIG_BLOCK_MAGIC
from fuin.apk.tools import find_build_tool, run_tool
from fuin.apk.zip_format import (
    LFH_FIXED_SIZE,
    CentralDirectoryEntry,
    ZipFormatError,
    find_eocd,
    is_zip64,
    local_header_extent,
    read_central_directory,
)

log = logging.getLogger(__name__)

DEFAULT_ALIGNMENT = 4
# Android 15 runs on devices with 16 KiB pages. An uncompressed `.so` that the
# loader maps in place must start on a page boundary or the app will not start.
PAGE_ALIGNMENT = 16384


def zipalign(
    apk_path: str,
    output_path: str,
    *,
    alignment: int = DEFAULT_ALIGNMENT,
    so_alignment: int | None = None,
) -> None:
    """Align stored (uncompressed) ZIP entries.

    ``so_alignment``, when given, is applied to stored ``lib/**/*.so`` entries
    instead of ``alignment`` — pass :data:`PAGE_ALIGNMENT` for 16 KiB devices.
    """
    bin_path = find_build_tool("zipalign")
    if bin_path and _run_sdk_zipalign(bin_path, apk_path, output_path, alignment, so_alignment):
        return
    _zipalign_py(apk_path, output_path, alignment=alignment, so_alignment=so_alignment)


def zipalign_file(
    apk_path: str,
    *,
    alignment: int = DEFAULT_ALIGNMENT,
    so_alignment: int | None = None,
) -> None:
    """Align an APK in place.

    Always uses the built-in aligner: the SDK binary refuses to write over its
    own input, and the callers that need this are already mid-pipeline on a
    temporary file.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        staged = os.path.join(tmpdir, "aligned.apk")
        _zipalign_py(apk_path, staged, alignment=alignment, so_alignment=so_alignment)
        shutil.copyfile(staged, apk_path)


def _run_sdk_zipalign(
    bin_path: str, apk_path: str, output_path: str, alignment: int, so_alignment: int | None
) -> bool:
    """Run the SDK binary. Returns False when the caller should fall back.

    ``-P`` only exists in build-tools 35 and later, so a rejected flag means
    "this binary is too old", not "this APK is broken".
    """
    argv = [bin_path, "-f", "-v"]
    if so_alignment is not None:
        argv += ["-P", str(so_alignment // 1024)]
    argv += [str(alignment), apk_path, output_path]

    result = run_tool(argv, check=False)
    if result.returncode == 0:
        return True
    if so_alignment is None:
        raise RuntimeError(f"zipalign failed:\n{result.stderr}")
    log.info("zipalign does not support -P, using the built-in aligner instead")
    return False


def _alignment_for(entry: CentralDirectoryEntry, alignment: int, so_alignment: int | None) -> int:
    """How many bytes ``entry``'s file data must be aligned to."""
    if not entry.is_stored:
        # Deflated data is copied to the heap before use, so its position in the
        # archive does not matter.
        return 1
    if (
        so_alignment is not None
        and entry.filename.startswith("lib/")
        and entry.filename.endswith(".so")
    ):
        return so_alignment
    return alignment


def _zipalign_py(
    apk_path: str,
    output_path: str,
    *,
    alignment: int = DEFAULT_ALIGNMENT,
    so_alignment: int | None = None,
) -> None:
    """Pure-Python zipalign.

    Rebuilds the archive entry by entry, padding each stored entry's local
    extra field so its data lands on a boundary, then rewrites the central
    directory and EOCD with the offsets the entries actually ended up at.
    """
    data = Path(apk_path).read_bytes()
    eocd = find_eocd(data)

    if is_zip64(data, eocd):
        raise ZipFormatError("ZIP64 archives are not supported by the built-in aligner")
    if data[eocd.cd_offset - 16 : eocd.cd_offset] == APK_SIG_BLOCK_MAGIC:
        raise ZipFormatError(
            "APK already carries a signing block — align before signing, not after"
        )

    entries = read_central_directory(data, eocd)

    out = bytearray()
    new_offsets: dict[int, int] = {}

    # Emit entries in the order their data appears in the file, not the order
    # the central directory lists them in.
    for entry in sorted(entries, key=lambda e: e.lfh_offset):
        data_start, entry_end = local_header_extent(data, entry)
        lfh = entry.lfh_offset
        name_len, extra_len = struct.unpack_from("<HH", data, lfh + 26)

        new_offset = len(out)
        want = _alignment_for(entry, alignment, so_alignment)
        header_len = LFH_FIXED_SIZE + name_len + extra_len
        padding = -(new_offset + header_len) % want

        header = bytearray(data[lfh : lfh + LFH_FIXED_SIZE])
        struct.pack_into("<H", header, 28, extra_len + padding)

        out += header
        out += data[lfh + LFH_FIXED_SIZE : data_start]  # name + original extra
        out += b"\x00" * padding
        out += data[data_start:entry_end]

        new_offsets[entry.offset] = new_offset

    new_cd_offset = len(out)
    for entry in entries:
        record = bytearray(data[entry.offset : entry.offset + entry.total_size])
        struct.pack_into("<I", record, 42, new_offsets[entry.offset])
        out += record
    new_cd_size = len(out) - new_cd_offset

    new_eocd = bytearray(data[eocd.offset :])
    struct.pack_into("<II", new_eocd, 12, new_cd_size, new_cd_offset)
    out += new_eocd

    Path(output_path).write_bytes(bytes(out))


def entry_alignment_report(apk_path: str) -> dict[str, int]:
    """Map every stored entry to the offset its file data starts at.

    Used by the tests, and by anything that needs to assert an APK really is
    aligned rather than that it merely survived the aligner.
    """
    data = Path(apk_path).read_bytes()
    eocd = find_eocd(data)
    offsets = {}
    for entry in read_central_directory(data, eocd):
        if entry.is_stored:
            data_start, _ = local_header_extent(data, entry)
            offsets[entry.filename] = data_start
    return offsets


__all__ = [
    "DEFAULT_ALIGNMENT",
    "PAGE_ALIGNMENT",
    "entry_alignment_report",
    "zipalign",
    "zipalign_file",
]
