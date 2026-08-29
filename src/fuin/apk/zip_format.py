"""Byte-level ZIP record parsing.

`zip_tools` works through :mod:`zipfile`; this module works on the raw bytes.
Alignment and v2 signing both need to know where the central directory and the
end-of-central-directory record actually sit in the file, which `zipfile` will
not tell you.

Only the fields fuin needs are parsed. Everything else is copied through
verbatim, so unknown extra fields and comments survive a round trip.
"""

import struct
from dataclasses import dataclass

from fuin.apk.constants import (
    ZIP64_EOCD_LOCATOR_MAGIC,
    ZIP_CD_MAGIC,
    ZIP_EOCD_MAGIC,
    ZIP_LOCAL_HEADER_MAGIC,
)

# Fixed-size prefixes, before the variable-length name/extra/comment fields.
EOCD_FIXED_SIZE = 22
CD_FIXED_SIZE = 46
LFH_FIXED_SIZE = 30

# A ZIP comment is a u16 length, so the EOCD can start at most this far back.
MAX_EOCD_SEARCH = EOCD_FIXED_SIZE + 0xFFFF

# General-purpose bit 3: sizes live in a trailing data descriptor, not the LFH.
FLAG_DATA_DESCRIPTOR = 0x08

METHOD_STORED = 0

# u32 fields use this sentinel when the real value lives in a ZIP64 record.
_ZIP64_SENTINEL_32 = 0xFFFFFFFF
_ZIP64_SENTINEL_16 = 0xFFFF


class ZipFormatError(ValueError):
    """The archive is not a ZIP fuin can process."""


@dataclass(frozen=True, slots=True)
class EndOfCentralDirectory:
    """The EOCD record, plus where it starts in the file."""

    offset: int
    entry_count: int
    cd_size: int
    cd_offset: int


@dataclass(frozen=True, slots=True)
class CentralDirectoryEntry:
    """One central-directory record.

    ``offset``/``total_size`` locate the record itself so it can be copied
    verbatim; ``lfh_offset`` points at the matching local file header.
    """

    offset: int
    total_size: int
    filename: str
    flags: int
    method: int
    compressed_size: int
    lfh_offset: int

    @property
    def has_data_descriptor(self) -> bool:
        return bool(self.flags & FLAG_DATA_DESCRIPTOR)

    @property
    def is_stored(self) -> bool:
        return self.method == METHOD_STORED


def find_eocd(data: bytes | bytearray) -> EndOfCentralDirectory:
    """Locate and parse the end-of-central-directory record.

    Scans backwards, and accepts a match only when the declared comment length
    reaches exactly the end of the file — the magic can otherwise appear inside
    compressed data.
    """
    if len(data) < EOCD_FIXED_SIZE:
        raise ZipFormatError("file is too small to be a ZIP")

    earliest = max(len(data) - MAX_EOCD_SEARCH, 0)
    for i in range(len(data) - EOCD_FIXED_SIZE, earliest - 1, -1):
        if data[i : i + 4] != ZIP_EOCD_MAGIC:
            continue
        comment_len = struct.unpack_from("<H", data, i + 20)[0]
        if i + EOCD_FIXED_SIZE + comment_len != len(data):
            continue
        entry_count, cd_size, cd_offset = struct.unpack_from("<HII", data, i + 10)
        return EndOfCentralDirectory(
            offset=i, entry_count=entry_count, cd_size=cd_size, cd_offset=cd_offset
        )
    raise ZipFormatError("no end-of-central-directory record — not a ZIP file")


def is_zip64(data: bytes | bytearray, eocd: EndOfCentralDirectory) -> bool:
    """Whether the archive relies on ZIP64 records for its real offsets."""
    if (
        eocd.cd_offset == _ZIP64_SENTINEL_32
        or eocd.cd_size == _ZIP64_SENTINEL_32
        or eocd.entry_count == _ZIP64_SENTINEL_16
    ):
        return True
    locator = eocd.offset - 20
    return locator >= 0 and data[locator : locator + 4] == ZIP64_EOCD_LOCATOR_MAGIC


def read_central_directory(
    data: bytes | bytearray, eocd: EndOfCentralDirectory
) -> list[CentralDirectoryEntry]:
    """Parse every central-directory record, in the order they are stored."""
    entries: list[CentralDirectoryEntry] = []
    pos = eocd.cd_offset
    end = eocd.cd_offset + eocd.cd_size
    if end > len(data):
        raise ZipFormatError("central directory extends past the end of the file")

    for _ in range(eocd.entry_count):
        if pos + CD_FIXED_SIZE > end:
            raise ZipFormatError("central directory is truncated")
        if data[pos : pos + 4] != ZIP_CD_MAGIC:
            raise ZipFormatError(f"bad central-directory signature at offset {pos}")

        flags, method = struct.unpack_from("<HH", data, pos + 8)
        compressed_size = struct.unpack_from("<I", data, pos + 20)[0]
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        lfh_offset = struct.unpack_from("<I", data, pos + 42)[0]

        total = CD_FIXED_SIZE + name_len + extra_len + comment_len
        if pos + total > end:
            raise ZipFormatError("central-directory record overruns the directory")
        name = bytes(data[pos + CD_FIXED_SIZE : pos + CD_FIXED_SIZE + name_len])

        entries.append(
            CentralDirectoryEntry(
                offset=pos,
                total_size=total,
                filename=name.decode("utf-8", "surrogateescape"),
                flags=flags,
                method=method,
                compressed_size=compressed_size,
                lfh_offset=lfh_offset,
            )
        )
        pos += total

    return entries


def local_header_extent(data: bytes | bytearray, entry: CentralDirectoryEntry) -> tuple[int, int]:
    """Return ``(data_start, entry_end)`` for one entry's local record.

    ``entry_end`` includes the trailing data descriptor when the entry has one,
    so ``data[entry.lfh_offset:entry_end]`` is the complete local record.
    """
    lfh = entry.lfh_offset
    if data[lfh : lfh + 4] != ZIP_LOCAL_HEADER_MAGIC:
        raise ZipFormatError(f"no local file header for {entry.filename!r} at offset {lfh}")

    name_len, extra_len = struct.unpack_from("<HH", data, lfh + 26)
    data_start = lfh + LFH_FIXED_SIZE + name_len + extra_len
    end = data_start + entry.compressed_size
    if end > len(data):
        raise ZipFormatError(f"entry data for {entry.filename!r} runs past the end of the file")

    if entry.has_data_descriptor:
        end += _data_descriptor_size(data, end)
    return data_start, end


def _data_descriptor_size(data: bytes | bytearray, start: int) -> int:
    """Size of the data descriptor at ``start``: 12 bytes, or 16 with its magic.

    The signature is optional in the spec, so its presence has to be sniffed.
    """
    if data[start : start + 4] == b"PK\x07\x08":
        return 16
    return 12
