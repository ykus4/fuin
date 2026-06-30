"""Pure-Python APK metadata extractor.

Parses AndroidManifest.xml (AXML binary) to extract package name, version,
permissions, component counts and the DEX file list.
"""

import logging
import os
import re
import zipfile

from fuin._constants import (
    AXML_FILE_MAGIC,
    CHUNK_RESOURCE_MAP,
    CHUNK_STRING_POOL,
    CHUNK_XML_END_ELEMENT,
    CHUNK_XML_START_ELEMENT,
    RES_MIN_SDK,
    RES_NAME,
    RES_TARGET_SDK,
    RES_VERSION_CODE,
    RES_VERSION_NAME,
)
from fuin._utils import fallback_package_name, read_u16, read_u32

log = logging.getLogger(__name__)

# Resource ID used for the "package" attribute on <manifest>. Some Android
# versions use the same constant as RES_VERSION_CODE; we keep them aliased.
_RES_PACKAGE = RES_VERSION_CODE


def _decode_string(data: bytes, strings_abs: int, offset: int, is_utf8: bool) -> str:
    try:
        if is_utf8:
            b0 = data[strings_abs + offset]
            offset += 2 if b0 & 0x80 else 1
            b0 = data[strings_abs + offset]
            if b0 & 0x80:
                length = ((b0 & 0x7F) << 8) | data[strings_abs + offset + 1]
                offset += 2
            else:
                length = b0
                offset += 1
            return data[strings_abs + offset : strings_abs + offset + length].decode(
                "utf-8", errors="replace"
            )
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
    except Exception:
        return ""


def _parse_string_pool(data: bytes, sp_offset: int) -> tuple[list[str], list[int]]:
    """Returns (pool_strings, resource_ids_from_res_map)."""
    if read_u32(data, sp_offset) != CHUNK_STRING_POOL:
        return [], []

    sp_size = read_u32(data, sp_offset + 4)
    sp_string_count = read_u32(data, sp_offset + 8)
    sp_flags = read_u32(data, sp_offset + 16)
    sp_strings_start = read_u32(data, sp_offset + 20)
    is_utf8 = bool(sp_flags & 0x100)

    offsets_start = sp_offset + 28
    strings_abs = sp_offset + sp_strings_start

    pool = [
        _decode_string(data, strings_abs, read_u32(data, offsets_start + i * 4), is_utf8)
        for i in range(sp_string_count)
    ]

    res_map_offset = sp_offset + sp_size
    res_ids: list[int] = []
    if res_map_offset + 8 <= len(data) and read_u32(data, res_map_offset) == CHUNK_RESOURCE_MAP:
        rm_size = read_u32(data, res_map_offset + 4)
        count = (rm_size - 8) // 4
        res_ids = [read_u32(data, res_map_offset + 8 + i * 4) for i in range(count)]

    return pool, res_ids


def _res_id(res_ids: list[int], attr_name_idx: int) -> int:
    return res_ids[attr_name_idx] if attr_name_idx < len(res_ids) else 0


def _pool_str(pool: list[str], idx: int) -> str:
    return pool[idx] if 0 <= idx < len(pool) else ""


def _parse_manifest(axml: bytes) -> dict:
    result: dict = {
        "package_name": "",
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": 0,
        "services": 0,
        "receivers": 0,
        "providers": 0,
    }

    if len(axml) < 8 or read_u32(axml, 0) != AXML_FILE_MAGIC:
        return result

    sp_offset = 8
    pool, res_ids = _parse_string_pool(axml, sp_offset)
    if not pool:
        return result

    sp_size = read_u32(axml, sp_offset + 4)
    rm_offset = sp_offset + sp_size
    rm_size = 0
    if rm_offset + 8 <= len(axml) and read_u32(axml, rm_offset) == CHUNK_RESOURCE_MAP:
        rm_size = read_u32(axml, rm_offset + 4)

    pos = sp_offset + sp_size + rm_size

    while pos + 8 <= len(axml):
        chunk_type = read_u32(axml, pos)
        chunk_size = read_u32(axml, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(axml):
            break

        if chunk_type == CHUNK_XML_START_ELEMENT:
            elem_name_idx = read_u32(axml, pos + 20)
            elem_name = _pool_str(pool, elem_name_idx)

            attr_start = read_u16(axml, pos + 24)
            attr_size = read_u16(axml, pos + 26)
            attr_count = read_u16(axml, pos + 28)
            attrs_base = pos + 16 + attr_start

            attrs: dict[int, tuple[int, str]] = {}
            for a in range(attr_count):
                a_off = attrs_base + a * attr_size
                if a_off + attr_size > len(axml):
                    break
                a_name_idx = read_u32(axml, a_off + 4)
                a_raw_val = read_u32(axml, a_off + 8)
                a_val_type = axml[a_off + 15]
                a_val_data = read_u32(axml, a_off + 16)
                raw_str = _pool_str(pool, a_raw_val) if a_val_type == 3 else ""
                attrs[_res_id(res_ids, a_name_idx)] = (a_val_data, raw_str)
                attrs[a_name_idx + 0x80000000] = (a_val_data, raw_str)

            def _str_val(rid: int) -> str:
                v = attrs.get(rid)
                if v:
                    return v[1] or _pool_str(pool, v[0])
                return ""

            def _int_val(rid: int) -> int | None:
                v = attrs.get(rid)
                return v[0] if v else None

            if elem_name == "manifest":
                result["package_name"] = _str_val(_RES_PACKAGE) or _str_val(0)
                if not result["package_name"]:
                    for i, s in enumerate(pool):
                        if s == "package":
                            v = attrs.get(i + 0x80000000)
                            if v and v[1]:
                                result["package_name"] = v[1]
                                break
                result["version_name"] = _str_val(RES_VERSION_NAME)
            elif elem_name == "uses-sdk":
                result["min_sdk"] = _int_val(RES_MIN_SDK)
                result["target_sdk"] = _int_val(RES_TARGET_SDK)
            elif elem_name == "uses-permission":
                perm = _str_val(RES_NAME)
                if not perm:
                    for i, s in enumerate(pool):
                        if s == "name":
                            v = attrs.get(i + 0x80000000)
                            if v and v[1]:
                                perm = v[1]
                                break
                if perm:
                    result["permissions"].append(perm)
            elif elem_name == "activity":
                result["activities"] += 1
            elif elem_name == "service":
                result["services"] += 1
            elif elem_name == "receiver":
                result["receivers"] += 1
            elif elem_name == "provider":
                result["providers"] += 1

        elif chunk_type == CHUNK_XML_END_ELEMENT:
            pass  # we don't track element nesting depth here

        pos += chunk_size

    return result


def get_apk_info(apk_path: str) -> dict:
    """Return rich metadata dict for an APK."""
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            axml = z.read("AndroidManifest.xml")
    except Exception as e:
        log.warning("failed to read APK %s: %s", apk_path, e)
        return {"package_name": "unknown", "error": str(e)}

    info = _parse_manifest(axml)

    dex_re = re.compile(r"^classes\d*\.dex$")
    info["dex_files"] = sorted(n for n in names if dex_re.match(n))
    info["dex_count"] = len(info["dex_files"])
    info["file_size_bytes"] = os.path.getsize(apk_path)
    info["entry_count"] = len(names)

    if not info["package_name"]:
        info["package_name"] = fallback_package_name(axml)

    return info
