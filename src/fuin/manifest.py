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
from pathlib import Path

from fuin._constants import ANDROID_NS, AXML_FILE_MAGIC, CHUNK_STRING_POOL
from fuin._utils import copy_zip_entries, read_u16, read_u32
from fuin.axml import (
    MANIFEST_NAME,
    TYPE_STRING,
    StringPool,
    encode_pool_string_utf16,
    iter_start_elements,
    read_string_pool,
)

log = logging.getLogger(__name__)

STUB_CLASS = "com.fuin.stub.StubApplication"


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
    magic = read_u32(data, 0)
    if magic != AXML_FILE_MAGIC:
        log.warning("unexpected AXML magic 0x%08x — trying fallback patcher", magic)
        return _patch_axml_fallback(data, original_app_class)

    sp_offset = 8  # string pool sits right after the file header
    sp = read_string_pool(data, sp_offset)
    if sp is None:
        log.warning(
            "expected string pool at offset 8, got 0x%08x — fallback", read_u32(data, sp_offset)
        )
        return _patch_axml_fallback(data, original_app_class)

    sp_chunk_size = sp.chunk_size
    sp_string_count = sp.string_count
    sp_style_count = sp.style_count
    sp_flags = sp.flags
    is_utf8 = sp.is_utf8
    offsets_start = sp.offsets_start
    strings_abs = sp.strings_abs
    pool = sp.strings

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
        target_idx, found_class = _find_application_name_attr(data, sp, sp_offset + sp_chunk_size)

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
            new_strings.append(encode_pool_string_utf16(STUB_CLASS))
        else:
            # Re-encode as-is from original bytes to preserve exact byte layout for others
            str_rel = read_u32(data, offsets_start + i * 4)
            char_count = read_u16(data, strings_abs + str_rel)
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
        orig_styles_start = read_u32(data, sp_offset + 24)
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

    # ResStringPool_header is 7 u32s (28 bytes).
    new_sp_header = struct.pack(
        "<IIIIIII",
        CHUNK_STRING_POOL,
        new_sp_size,
        sp_string_count,
        sp_style_count,
        sp_flags,
        new_sp_strings_start,
        (new_sp_strings_start + len(new_strings_blob)) if sp_style_count else 0,
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
    old_file_size = read_u32(data, 4)
    new_file_size = old_file_size + len(new_sp_chunk) - sp_chunk_size

    result = bytearray(data)
    # Replace string pool chunk
    result[sp_offset : sp_offset + sp_chunk_size] = new_sp_chunk
    # Update file size in header
    struct.pack_into("<I", result, 4, new_file_size)

    return bytes(result), found_class


def _find_application_name_attr(
    data: bytes, pool: StringPool, chunks_start: int
) -> tuple[int | None, str]:
    """
    Walk XML element chunks to find the android:name attribute on <application>.
    Returns (pool_index, string_value) or (None, "").
    """
    ns_idx = pool.index_of(ANDROID_NS)
    name_attr_idx = pool.index_of("name")
    app_tag_idx = pool.index_of("application")

    for elem in iter_start_elements(data, chunks_start):
        if elem.name_index != app_tag_idx:
            continue

        for attr in elem.attributes:
            if attr.ns_index != ns_idx or attr.name_index != name_attr_idx:
                continue
            if attr.value_type == TYPE_STRING:
                val_idx = attr.value_data
            elif 0 <= attr.raw_value_index < len(pool.strings):
                val_idx = attr.raw_value_index
            else:
                continue
            s = pool.get(val_idx)
            if s and s != STUB_CLASS:
                return val_idx, s

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
        manifest_data = zin.read(MANIFEST_NAME)

    patched, found_class = _patch_axml(manifest_data, original_app_class)

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        copy_zip_entries(zin, zout, replace={MANIFEST_NAME: patched})

    Path(output_path).write_bytes(buf.getvalue())

    return found_class
