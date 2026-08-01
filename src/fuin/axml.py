"""Android Binary XML (AXML) reading primitives.

Shared by the read-only inspector (:mod:`fuin.apk_info`) and the string-pool
rewriter (:mod:`fuin.manifest`), which each used to carry an independent
implementation of the same binary format — same offsets, same extended-length
bit tricks, differing only in error handling.

Layout (chunk-based):
  0x00080003  — XML document header
  0x001C0001  — String pool chunk
  0x00180002  — Resource map chunk
  0x00100102  — Start element
  0x00100103  — End element
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from fuin._constants import (
    AXML_FILE_MAGIC,
    CHUNK_RESOURCE_MAP,
    CHUNK_STRING_POOL,
    CHUNK_XML_START_ELEMENT,
)
from fuin._utils import read_u16, read_u32

MANIFEST_NAME = "AndroidManifest.xml"

# ResValue type byte for a string reference into the pool.
TYPE_STRING = 0x03

# Flag in the string-pool header marking UTF-8 (rather than UTF-16LE) strings.
_FLAG_UTF8 = 0x100

# ResStringPool_header is 7 u32s; the offsets array follows it.
_POOL_HEADER_SIZE = 28


def decode_pool_string(data: bytes, strings_abs: int, offset: int, is_utf8: bool) -> str:
    """Decode one string from the pool's data section.

    Both encodings prefix the payload with a length that switches to two bytes
    when the high bit is set.
    """
    if is_utf8:
        # char count, then byte count, then the bytes, then a NUL.
        b0 = data[strings_abs + offset]
        offset += 2 if b0 & 0x80 else 1
        b0 = data[strings_abs + offset]
        if b0 & 0x80:
            length = ((b0 & 0x7F) << 8) | data[strings_abs + offset + 1]
            offset += 2
        else:
            length = b0
            offset += 1
        raw = data[strings_abs + offset : strings_abs + offset + length]
        return raw.decode("utf-8", errors="replace")

    # UTF-16LE: char count (u16), chars, NUL u16.
    char_count = read_u16(data, strings_abs + offset)
    if char_count & 0x8000:
        lo = data[strings_abs + offset + 1]
        hi = data[strings_abs + offset + 2] & 0x7F
        char_count = (hi << 8) | lo
        offset += 4
    else:
        offset += 2
    raw = data[strings_abs + offset : strings_abs + offset + char_count * 2]
    return raw.decode("utf-16-le", errors="replace")


def encode_pool_string_utf16(s: str) -> bytes:
    """Encode a string as an AXML UTF-16LE pool entry: u16 count + data + NUL."""
    if len(s) > 0x7FFF:
        raise ValueError("String too long for AXML string pool")
    return struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"


@dataclass(frozen=True)
class StringPool:
    """A decoded AXML string pool, plus the offsets needed to rewrite it."""

    strings: list[str]
    chunk_size: int
    string_count: int
    style_count: int
    flags: int
    # Offset of the string data, relative to the start of the chunk.
    strings_start: int
    # Absolute offsets into the AXML buffer.
    offsets_start: int
    strings_abs: int
    is_utf8: bool
    # Resource IDs from the resource-map chunk, parallel to the first N strings.
    res_ids: list[int] = field(default_factory=list)

    def get(self, index: int) -> str:
        """String at ``index``, or ``""`` when out of range."""
        return self.strings[index] if 0 <= index < len(self.strings) else ""

    def index_of(self, value: str) -> int | None:
        """First index holding ``value``, or None."""
        try:
            return self.strings.index(value)
        except ValueError:
            return None

    def res_id(self, name_index: int) -> int:
        """Resource ID for an attribute name index, or 0 when absent."""
        return self.res_ids[name_index] if 0 <= name_index < len(self.res_ids) else 0


def read_string_pool(data: bytes, sp_offset: int) -> StringPool | None:
    """Parse the string pool at ``sp_offset``. Returns None if it isn't one."""
    if len(data) < sp_offset + _POOL_HEADER_SIZE:
        return None
    if read_u32(data, sp_offset) != CHUNK_STRING_POOL:
        return None

    chunk_size = read_u32(data, sp_offset + 4)
    string_count = read_u32(data, sp_offset + 8)
    style_count = read_u32(data, sp_offset + 12)
    flags = read_u32(data, sp_offset + 16)
    strings_start = read_u32(data, sp_offset + 20)

    is_utf8 = bool(flags & _FLAG_UTF8)
    offsets_start = sp_offset + _POOL_HEADER_SIZE
    strings_abs = sp_offset + strings_start

    strings: list[str] = []
    for i in range(string_count):
        try:
            rel = read_u32(data, offsets_start + i * 4)
            strings.append(decode_pool_string(data, strings_abs, rel, is_utf8))
        except Exception:
            # A single malformed entry must not lose the rest of the pool;
            # indices have to stay aligned, so append a placeholder.
            strings.append("")

    res_ids: list[int] = []
    rm_offset = sp_offset + chunk_size
    if rm_offset + 8 <= len(data) and read_u32(data, rm_offset) == CHUNK_RESOURCE_MAP:
        rm_size = read_u32(data, rm_offset + 4)
        res_ids = [read_u32(data, rm_offset + 8 + i * 4) for i in range((rm_size - 8) // 4)]

    return StringPool(
        strings=strings,
        chunk_size=chunk_size,
        string_count=string_count,
        style_count=style_count,
        flags=flags,
        strings_start=strings_start,
        offsets_start=offsets_start,
        strings_abs=strings_abs,
        is_utf8=is_utf8,
        res_ids=res_ids,
    )


@dataclass(frozen=True)
class Attribute:
    """One attribute on a start element, straight out of the binary form."""

    ns_index: int
    name_index: int
    raw_value_index: int
    value_type: int
    value_data: int


@dataclass(frozen=True)
class StartElement:
    """A start-element chunk: its name and attributes."""

    name_index: int
    attributes: list[Attribute]


def body_offset(data: bytes) -> int | None:
    """Offset of the first element chunk, i.e. past the pool and resource map.

    Returns None when ``data`` is not AXML or has no string pool.
    """
    if len(data) < 8 or read_u32(data, 0) != AXML_FILE_MAGIC:
        return None
    pool = read_string_pool(data, 8)
    if pool is None:
        return None

    pos = 8 + pool.chunk_size
    if pos + 8 <= len(data) and read_u32(data, pos) == CHUNK_RESOURCE_MAP:
        pos += read_u32(data, pos + 4)
    return pos


def iter_start_elements(data: bytes, start: int) -> Iterator[StartElement]:
    """Walk element chunks from ``start``, yielding every start element.

    Stops at the first structurally impossible chunk rather than raising.
    """
    pos = start
    while pos + 8 <= len(data):
        chunk_type = read_u32(data, pos)
        chunk_size = read_u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(data):
            return

        if chunk_type == CHUNK_XML_START_ELEMENT:
            yield StartElement(
                name_index=read_u32(data, pos + 20),
                attributes=list(_read_attributes(data, pos)),
            )

        pos += chunk_size


def _read_attributes(data: bytes, elem_pos: int) -> Iterator[Attribute]:
    """Decode the attribute array of the start element at ``elem_pos``.

    Header is 4 u32s, then lineNumber/comment/ns/name, then attrStart (which
    is measured from the end of the 4-u32 header), attrSize and attrCount.
    """
    attr_start = read_u16(data, elem_pos + 24)
    attr_size = read_u16(data, elem_pos + 26)
    attr_count = read_u16(data, elem_pos + 28)
    base = elem_pos + 16 + attr_start

    for i in range(attr_count):
        off = base + i * attr_size
        if off + attr_size > len(data):
            return
        yield Attribute(
            ns_index=read_u32(data, off),
            name_index=read_u32(data, off + 4),
            raw_value_index=read_u32(data, off + 8),
            # ResValue is size u16, res0 u8, type u8, data u32.
            value_type=data[off + 15],
            value_data=read_u32(data, off + 16),
        )
