"""
Pure-Python APK metadata extractor.

Parses AndroidManifest.xml (AXML binary) to extract:
  - package name, version, minSdk, targetSdk
  - declared permissions
  - activity / service / receiver / provider counts
  - DEX file list
"""

import logging
import re
import struct
import zipfile

log = logging.getLogger(__name__)

# AXML chunk types
_CHUNK_STRING_POOL = 0x001C0001
_CHUNK_RESOURCE_MAP = 0x00180002
_CHUNK_XML_START_NS = 0x00100100
_CHUNK_XML_END_NS = 0x00100101
_CHUNK_XML_START_ELEMENT = 0x00100102
_CHUNK_XML_END_ELEMENT = 0x00100103
_CHUNK_XML_CDATA = 0x00100104

# Android resource IDs for common attributes
_RES_PACKAGE = 0x0101021B
_RES_VERSION_CODE = 0x0101021B
_RES_VERSION_NAME = 0x0101021C
_RES_MIN_SDK = 0x0101020C
_RES_TARGET_SDK = 0x01010270
_RES_NAME = 0x01010003


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


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
        else:
            char_count = _read_u16(data, strings_abs + offset)
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
    chunk_type = _read_u32(data, sp_offset)
    if chunk_type != _CHUNK_STRING_POOL:
        return [], []

    sp_size = _read_u32(data, sp_offset + 4)
    sp_string_count = _read_u32(data, sp_offset + 8)
    sp_flags = _read_u32(data, sp_offset + 16)
    sp_strings_start = _read_u32(data, sp_offset + 20)
    is_utf8 = bool(sp_flags & 0x100)

    offsets_start = sp_offset + 28
    strings_abs = sp_offset + sp_strings_start

    pool = []
    for i in range(sp_string_count):
        str_rel = _read_u32(data, offsets_start + i * 4)
        pool.append(_decode_string(data, strings_abs, str_rel, is_utf8))

    # Resource map chunk immediately follows string pool
    res_map_offset = sp_offset + sp_size
    res_ids: list[int] = []
    if res_map_offset + 8 <= len(data):
        rm_type = _read_u32(data, res_map_offset)
        if rm_type == _CHUNK_RESOURCE_MAP:
            rm_size = _read_u32(data, res_map_offset + 4)
            count = (rm_size - 8) // 4
            for i in range(count):
                res_ids.append(_read_u32(data, res_map_offset + 8 + i * 4))

    return pool, res_ids


def _parse_manifest(axml: bytes) -> dict:
    """Parse AXML binary, return dict of manifest metadata."""
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

    if len(axml) < 8 or _read_u32(axml, 0) != 0x00080003:
        return result

    sp_offset = 8
    pool, res_ids = _parse_string_pool(axml, sp_offset)
    if not pool:
        return result

    sp_size = _read_u32(axml, sp_offset + 4)
    rm_offset = sp_offset + sp_size
    rm_size = 0
    if rm_offset + 8 <= len(axml) and _read_u32(axml, rm_offset) == _CHUNK_RESOURCE_MAP:
        rm_size = _read_u32(axml, rm_offset + 4)

    def _res_id(attr_name_idx: int) -> int:
        if attr_name_idx < len(res_ids):
            return res_ids[attr_name_idx]
        return 0

    def _pool_str(idx: int) -> str:
        if 0 <= idx < len(pool):
            return pool[idx]
        return ""

    pos = sp_offset + sp_size + rm_size
    current_elem: list[str] = []

    while pos + 8 <= len(axml):
        chunk_type = _read_u32(axml, pos)
        chunk_size = _read_u32(axml, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(axml):
            break

        if chunk_type == _CHUNK_XML_START_ELEMENT:
            elem_name_idx = _read_u32(axml, pos + 20)
            elem_name = _pool_str(elem_name_idx)
            current_elem.append(elem_name)

            attr_start = _read_u16(axml, pos + 24)
            attr_size = _read_u16(axml, pos + 26)
            attr_count = _read_u16(axml, pos + 28)
            attrs_base = pos + 16 + attr_start

            attrs: dict[int, tuple[int, str]] = {}  # res_id → (val_data, raw_str_idx)
            for a in range(attr_count):
                a_off = attrs_base + a * attr_size
                if a_off + attr_size > len(axml):
                    break
                a_name_idx = _read_u32(axml, a_off + 4)
                a_raw_val = _read_u32(axml, a_off + 8)
                a_val_type = axml[a_off + 15]
                a_val_data = _read_u32(axml, a_off + 16)
                rid = _res_id(a_name_idx)
                attrs[rid] = (a_val_data, _pool_str(a_raw_val) if a_val_type == 3 else "")
                # also store by name string for fallback
                attrs[a_name_idx + 0x80000000] = (
                    a_val_data,
                    _pool_str(a_raw_val) if a_val_type == 3 else "",
                )

            def _str_val(rid: int, fallback_name: str = "") -> str:
                v = attrs.get(rid)
                if v:
                    if v[1]:
                        return v[1]
                    return _pool_str(v[0])
                return ""

            def _int_val(rid: int) -> int | None:
                v = attrs.get(rid)
                if v:
                    return v[0]
                return None

            if elem_name == "manifest":
                result["package_name"] = _str_val(_RES_PACKAGE) or _str_val(0)
                # Fallback: scan attrs by name index for "package"
                if not result["package_name"]:
                    for i, s in enumerate(pool):
                        if s == "package":
                            v = attrs.get(i + 0x80000000)
                            if v and v[1]:
                                result["package_name"] = v[1]
                                break
                result["version_name"] = _str_val(_RES_VERSION_NAME)

            elif elem_name == "uses-sdk":
                result["min_sdk"] = _int_val(_RES_MIN_SDK)
                result["target_sdk"] = _int_val(_RES_TARGET_SDK)

            elif elem_name == "uses-permission":
                perm = _str_val(_RES_NAME)
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

        elif chunk_type == _CHUNK_XML_END_ELEMENT:
            if current_elem:
                current_elem.pop()

        pos += chunk_size

    return result


def get_apk_info(apk_path: str) -> dict:
    """
    Return rich metadata dict for an APK:
      package_name, version_name, min_sdk, target_sdk,
      permissions (list), activities, services, receivers, providers,
      dex_files (list of filenames), file_size_bytes, entry_count
    """
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
    info["file_size_bytes"] = __import__("os").path.getsize(apk_path)
    info["entry_count"] = len(names)

    # Fallback package name from raw bytes if AXML parser missed it
    if not info["package_name"]:
        info["package_name"] = _fallback_package_name(axml)

    return info


def _fallback_package_name(axml: bytes) -> str:
    idx = axml.find(b"package")
    if idx == -1:
        return "unknown"
    chunk = axml[idx : idx + 256]
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = chunk.decode(encoding, errors="ignore")
            for p in text.split():
                if "." in p and p.replace(".", "").replace("_", "").isalnum():
                    return p
        except Exception:
            pass
    return "unknown"
