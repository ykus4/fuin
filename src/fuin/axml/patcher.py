"""
Patch AndroidManifest.xml (Android Binary XML / AXML format).

This is a proper structural AXML parser that rewrites the string pool in-place.
It handles the common production case reliably without external dependencies.

AXML format (chunk-based):
  0x00080003  — XML document header
  0x001C0001  — String pool chunk
  0x00080180  — Resource map chunk
  0x00100102  — Start element
  0x00100103  — End element
  ...
"""

import logging
import re
import struct

from fuin.axml.constants import ANDROID_NS, AXML_FILE_MAGIC, CHUNK_STRING_POOL, TYPE_STRING
from fuin.axml.reader import (
    StringPool,
    encode_pool_string_utf16,
    iter_start_elements,
    raw_pool_entry,
    read_string_pool,
    read_u32,
)
from fuin.contract import STUB_CLASS

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Main patcher
# ---------------------------------------------------------------------------


def patch_axml(data: bytes, original_app_class: str | None) -> tuple[bytes, str]:
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
        return _patch_fallback(data, original_app_class)

    sp_offset = 8  # string pool sits right after the file header
    sp = read_string_pool(data, sp_offset)
    if sp is None:
        # Do not read the chunk type back for the message: a truncated manifest
        # is exactly the case that lands here, and there may be nothing to read.
        log.warning("no usable string pool at offset %d — fallback", sp_offset)
        return _patch_fallback(data, original_app_class)

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
        return _patch_fallback(data, found_class or original_app_class)

    # Build new pool: replace target string, recalculate offsets
    new_strings: list[bytes] = []
    for i in range(len(pool)):
        if i == target_idx:
            new_strings.append(encode_pool_string_utf16(STUB_CLASS))
        else:
            # Copied verbatim to preserve the exact byte layout of every other
            # entry — the length decoding lives in the reader, not here.
            str_rel = read_u32(data, offsets_start + i * 4)
            new_strings.append(raw_pool_entry(data, strings_abs, str_rel, is_utf8))

    # Compute new offsets
    new_offsets: list[int] = []
    pos = 0
    for blob in new_strings:
        new_offsets.append(pos)
        pos += len(blob)

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


# A run of 4+ ASCII characters encoded as UTF-16LE.
_UTF16_ASCII_RUN = re.compile(rb"(?:[a-zA-Z0-9_./$]\x00){4,}")


def _patch_fallback(data: bytes, original_app_class: str | None) -> tuple[bytes, str]:
    """Byte-level fallback for manifests the structural parser cannot lay out.

    This can only ever do a *same-length* substitution. AXML string offsets are
    absolute, so changing the byte length of any pool entry shifts every
    following chunk and leaves a manifest Android will not parse. When the
    replacement does not fit, the manifest is returned untouched with an empty
    class name — which is what ``strict_manifest_patch`` checks, so the pack
    fails loudly instead of shipping a broken APK.
    """
    stub_utf16 = STUB_CLASS.encode("utf-16-le")

    if original_app_class:
        target_utf16 = original_app_class.encode("utf-16-le")
        if target_utf16 in data:
            if len(target_utf16) != len(stub_utf16):
                log.warning(
                    "fallback patcher cannot replace %r with %s: %d bytes vs %d",
                    original_app_class,
                    STUB_CLASS,
                    len(target_utf16),
                    len(stub_utf16),
                )
                return data, ""
            return data.replace(target_utf16, stub_utf16, 1), original_app_class

    for match in _UTF16_ASCII_RUN.finditer(data):
        try:
            found = match.group(0).decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if "." not in found or len(found) <= 4 or found.startswith("http"):
            continue
        if "Application" not in found and "App" not in found:
            continue

        original = found.encode("utf-16-le")
        if len(original) != len(stub_utf16):
            log.warning(
                "fallback patcher found %r but it is %d bytes, not %d — leaving the manifest alone",
                found,
                len(original),
                len(stub_utf16),
            )
            return data, ""
        return data[: match.start()] + stub_utf16 + data[match.end() :], found

    return data, ""
