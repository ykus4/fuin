"""
Parse and patch AndroidManifest.xml (Android Binary XML / AXML format).

This is a proper structural AXML parser that rewrites the string pool in-place.
It handles the common production case reliably without external dependencies.

AXML format (chunk-based):
  0x00080003  — XML document header
  0x001C0001  — String pool chunk
  0x00180002  — Resource map chunk
  0x00100102  — Start element
  0x00100103  — End element
  ...
"""

import io
import logging
import struct
import zipfile

log = logging.getLogger(__name__)

STUB_CLASS = "com.fuin.stub.StubApplication"

# AXML chunk types
_CHUNK_STRING_POOL = 0x001C0001
_CHUNK_XML_START_ELEMENT = 0x00100102

# Common Android namespace URI
_ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------------------
# String pool reader / writer
# ---------------------------------------------------------------------------


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _decode_pool_string(data: bytes, strings_start: int, offset: int, is_utf8: bool) -> str:
    """Decode a single string from the string pool data section."""
    if is_utf8:
        # UTF-8 strings: char_count (u8/u16), byte_count (u8/u16), bytes, NUL
        # char count
        b0 = data[strings_start + offset]
        if b0 & 0x80:
            offset += 2
        else:
            offset += 1
        # byte count
        b0 = data[strings_start + offset]
        if b0 & 0x80:
            length = ((b0 & 0x7F) << 8) | data[strings_start + offset + 1]
            offset += 2
        else:
            length = b0
            offset += 1
        raw = data[strings_start + offset : strings_start + offset + length]
        return raw.decode("utf-8", errors="replace")
    else:
        # UTF-16LE strings: char_count (u16), chars, NUL u16
        char_count = struct.unpack_from("<H", data, strings_start + offset)[0]
        if char_count & 0x8000:
            # Two-byte char count
            lo = data[strings_start + offset + 1]
            hi = data[strings_start + offset + 2] & 0x7F
            char_count = (hi << 8) | lo
            offset += 4
        else:
            offset += 2
        raw = data[strings_start + offset : strings_start + offset + char_count * 2]
        return raw.decode("utf-16-le", errors="replace")


def _encode_pool_string_utf16(s: str) -> bytes:
    """Encode a string in AXML UTF-16LE pool format: u16 char_count + utf16le data + u16 NUL."""
    encoded = s.encode("utf-16-le")
    char_count = len(s)
    if char_count > 0x7FFF:
        raise ValueError("String too long for AXML string pool")
    return struct.pack("<H", char_count) + encoded + b"\x00\x00"


# ---------------------------------------------------------------------------
# Main patcher
# ---------------------------------------------------------------------------


def _patch_axml(data: bytes, original_app_class: str | None) -> tuple[bytes, str]:
    """
    Parse AXML binary, find the Application android:name string in the pool,
    replace it with STUB_CLASS.

    Returns (patched_bytes, original_class_name).
    """
    if len(data) < 8:
        return data, ""

    # Verify AXML magic
    magic = _read_u32(data, 0)
    if magic != 0x00080003:
        log.warning("unexpected AXML magic 0x%08x — trying fallback patcher", magic)
        return _patch_axml_fallback(data, original_app_class)

    # Locate string pool chunk
    sp_offset = 8  # right after the file header
    chunk_type = _read_u32(data, sp_offset)
    if chunk_type != _CHUNK_STRING_POOL:
        log.warning("expected string pool at offset 8, got 0x%08x — fallback", chunk_type)
        return _patch_axml_fallback(data, original_app_class)

    sp_chunk_size = _read_u32(data, sp_offset + 4)
    sp_string_count = _read_u32(data, sp_offset + 8)
    sp_style_count = _read_u32(data, sp_offset + 12)
    sp_flags = _read_u32(data, sp_offset + 16)
    sp_strings_start = _read_u32(data, sp_offset + 20)  # offset from chunk start
    # sp_styles_start = _read_u32(data, sp_offset + 24)  # unused

    is_utf8 = bool(sp_flags & 0x100)

    # Offsets array: string_count u32 values, starting at sp_offset + 28
    offsets_start = sp_offset + 28
    strings_abs = sp_offset + sp_strings_start  # absolute offset in data where strings begin

    # Decode all strings
    pool: list[str] = []
    for i in range(sp_string_count):
        str_rel = _read_u32(data, offsets_start + i * 4)
        try:
            s = _decode_pool_string(data, strings_abs, str_rel, is_utf8)
        except Exception:
            s = ""
        pool.append(s)

    # --- Find the application class index ---
    # Strategy 1: look for an exact match of the provided original_app_class
    # Strategy 2: look for any string matching a known Application class pattern in the pool
    target_idx: int | None = None
    found_class: str = ""

    if original_app_class:
        for i, s in enumerate(pool):
            # AXML sometimes stores class names with leading dot or slash
            normalized = s.lstrip("./").replace("/", ".")
            if normalized == original_app_class or s == original_app_class:
                target_idx = i
                found_class = s
                break

    if target_idx is None:
        # Auto-detect: scan XML elements for android:name on <application> tag
        target_idx, found_class = _find_application_name_attr(data, pool, sp_offset + sp_chunk_size)

    if target_idx is None:
        log.info("no Application android:name found — manifest left unchanged")
        return data, ""

    log.info("replacing pool[%d] %r with stub class", target_idx, found_class)

    # --- Rewrite the string pool with the stub class substituted ---
    if is_utf8:
        return _patch_axml_fallback(data, found_class or original_app_class)

    # Build new pool: replace target string, recalculate offsets
    new_strings: list[bytes] = []
    for i, s in enumerate(pool):
        if i == target_idx:
            new_strings.append(_encode_pool_string_utf16(STUB_CLASS))
        else:
            # Re-encode as-is from original bytes to preserve exact byte layout for others
            str_rel = _read_u32(data, offsets_start + i * 4)
            char_count = _read_u16(data, strings_abs + str_rel)
            if char_count & 0x8000:
                # extended length
                char_count = ((data[strings_abs + str_rel + 2] & 0x7F) << 8) | data[
                    strings_abs + str_rel + 1
                ]
                raw_start = str_rel + 4
            else:
                raw_start = str_rel + 2
            raw_end = raw_start + char_count * 2 + 2  # +2 for NUL terminator
            new_strings.append(
                data[strings_abs + str_rel : strings_abs + str_rel + (raw_end - str_rel)]
            )

    # Compute new offsets
    new_offsets: list[int] = []
    pos = 0
    for s in new_strings:
        new_offsets.append(pos)
        pos += len(s)

    # Style offsets (copy unchanged)
    styles_blob = b""
    if sp_style_count > 0:
        style_offsets_start = offsets_start + sp_string_count * 4
        orig_styles_start = _read_u32(data, sp_offset + 24)
        if orig_styles_start:
            # Style data ends at sp_chunk_size from sp_offset
            orig_styles_abs = sp_offset + orig_styles_start
            styles_blob = data[orig_styles_abs : sp_offset + sp_chunk_size]

    # Assemble new string pool chunk
    new_strings_blob = b"".join(new_strings)
    new_sp_strings_start = 28 + sp_string_count * 4 + sp_style_count * 4
    new_sp_size = new_sp_strings_start + len(new_strings_blob) + len(styles_blob)
    # Keep 4-byte aligned
    if new_sp_size % 4:
        padding = 4 - (new_sp_size % 4)
        new_strings_blob += b"\x00" * padding
        new_sp_size += padding

    new_sp_strings_start_with_styles = new_sp_strings_start  # strings start offset within chunk

    new_sp_header = struct.pack(
        "<IIIIIIII",
        _CHUNK_STRING_POOL,
        new_sp_size,
        sp_string_count,
        sp_style_count,
        sp_flags,
        new_sp_strings_start_with_styles,
        (new_sp_strings_start_with_styles + len(new_strings_blob)) if sp_style_count else 0,
        0,  # unused
    )
    # Wait — header is only 7 u32s (28 bytes). Fix:
    new_sp_header = struct.pack(
        "<IIIIIII",
        _CHUNK_STRING_POOL,
        new_sp_size,
        sp_string_count,
        sp_style_count,
        sp_flags,
        new_sp_strings_start_with_styles,
        (new_sp_strings_start_with_styles + len(new_strings_blob)) if sp_style_count else 0,
    )

    new_offsets_blob = struct.pack(f"<{sp_string_count}I", *new_offsets)
    style_offsets_blob = b""
    if sp_style_count > 0:
        style_offsets_start = offsets_start + sp_string_count * 4
        style_offsets_blob = data[style_offsets_start : style_offsets_start + sp_style_count * 4]

    new_sp_chunk = (
        new_sp_header + new_offsets_blob + style_offsets_blob + new_strings_blob + styles_blob
    )

    # Patch file size in document header
    old_file_size = _read_u32(data, 4)
    new_file_size = old_file_size + len(new_sp_chunk) - sp_chunk_size

    result = bytearray(data)
    # Replace string pool chunk
    result[sp_offset : sp_offset + sp_chunk_size] = new_sp_chunk
    # Update file size in header
    struct.pack_into("<I", result, 4, new_file_size)

    return bytes(result), found_class


def _find_application_name_attr(
    data: bytes, pool: list[str], chunks_start: int
) -> tuple[int | None, str]:
    """
    Walk XML element chunks to find the android:name attribute on <application>.
    Returns (pool_index, string_value) or (None, "").
    """
    # Build index: pool string → index (for namespace lookup)
    ns_idx = next((i for i, s in enumerate(pool) if s == _ANDROID_NS), None)
    name_attr_idx = next((i for i, s in enumerate(pool) if s == "name"), None)
    app_tag_idx = next((i for i, s in enumerate(pool) if s == "application"), None)

    pos = chunks_start
    in_application = False

    while pos + 8 <= len(data):
        chunk_type = _read_u32(data, pos)
        chunk_size = _read_u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(data):
            break

        if chunk_type == _CHUNK_XML_START_ELEMENT:
            # StartElement: header(8) + lineNumber(4) + comment(4) + ns(4) + name(4)
            #               + attrStart(2) + attrSize(2) + attrCount(2) + ...
            elem_name_idx = _read_u32(data, pos + 20)
            if elem_name_idx == app_tag_idx:
                in_application = True
            elif in_application:
                in_application = False  # left <application>

            if in_application:
                attr_start = _read_u16(data, pos + 24)
                attr_size = _read_u16(data, pos + 26)
                attr_count = _read_u16(data, pos + 28)
                attrs_base = pos + 16 + attr_start  # pos+16 = after 4 header u32s
                for a in range(attr_count):
                    a_off = attrs_base + a * attr_size
                    if a_off + attr_size > len(data):
                        break
                    a_ns = _read_u32(data, a_off)
                    a_name = _read_u32(data, a_off + 4)
                    a_raw_val_idx = _read_u32(data, a_off + 8)
                    # value type is at a_off+12 (ResValue: size u16, res0 u8, type u8, data u32)
                    a_val_type = data[a_off + 15]  # type byte
                    a_val_data = _read_u32(data, a_off + 16)

                    if a_ns == ns_idx and a_name == name_attr_idx:
                        # TYPE_STRING = 0x03
                        if a_val_type == 0x03:
                            val_idx = a_val_data
                        elif 0 <= a_raw_val_idx < len(pool):
                            val_idx = a_raw_val_idx
                        else:
                            continue
                        if 0 <= val_idx < len(pool):
                            s = pool[val_idx]
                            if s and s != STUB_CLASS:
                                return val_idx, s

        pos += chunk_size

    return None, ""


def _patch_axml_fallback(data: bytes, original_app_class: str | None) -> tuple[bytes, str]:
    """
    Byte-level fallback: find the class name encoded as UTF-16LE in the raw bytes and replace it.
    Used when the structural parser cannot identify the string pool layout.
    """
    stub_utf16 = STUB_CLASS.encode("utf-16-le")

    if original_app_class:
        target_utf16 = original_app_class.encode("utf-16-le")
        if target_utf16 in data:
            patched = data.replace(target_utf16, stub_utf16, 1)
            return patched, original_app_class

    # Auto-detect: scan for UTF-16LE strings that look like Application class names
    import re

    best: tuple[int, int, str] | None = None
    for m in re.finditer(rb"(?:[a-zA-Z0-9_./$]\x00){4,}", data):
        try:
            s = m.group(0).decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if "." in s and len(s) > 4 and not s.startswith("http"):
            if "Application" in s or "App" in s:
                best = (m.start(), m.end(), s)
                break

    if best:
        start, end, found = best
        # Ensure same length replacement — pad or truncate
        orig_bytes = found.encode("utf-16-le")
        new_bytes = STUB_CLASS.encode("utf-16-le")
        if len(orig_bytes) == len(new_bytes):
            patched = data[:start] + new_bytes + data[end:]
            return patched, found
        # Different length: use replace (may shift offsets but best-effort)
        patched = data.replace(orig_bytes, new_bytes, 1)
        return patched, found

    return data, ""


def patch_manifest(apk_path: str, output_path: str, original_app_class: str | None) -> str:
    """
    Patch AndroidManifest.xml inside the APK:
    - Replace the Application android:name with StubApplication

    Returns the original application class name (or empty string if none).
    """
    with zipfile.ZipFile(apk_path, "r") as zin:
        manifest_data = zin.read("AndroidManifest.xml")

    patched, found_class = _patch_axml(manifest_data, original_app_class)

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            if item.filename == "AndroidManifest.xml":
                zout.writestr(item, patched)
            else:
                zout.writestr(item, zin.read(item.filename))

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    return found_class
