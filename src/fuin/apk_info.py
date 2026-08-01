"""Pure-Python APK metadata extractor.

Parses AndroidManifest.xml (AXML binary) to extract package name, version,
permissions, component counts and the DEX file list.
"""

import logging
import os
import zipfile

from fuin import axml as axml_mod
from fuin._constants import (
    DEX_NAME_RE,
    RES_MIN_SDK,
    RES_NAME,
    RES_TARGET_SDK,
    RES_VERSION_CODE,
    RES_VERSION_NAME,
)
from fuin._utils import fallback_package_name

log = logging.getLogger(__name__)


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

    pos = axml_mod.body_offset(axml)
    if pos is None:
        return result
    pool = axml_mod.read_string_pool(axml, 8)
    if pool is None or not pool.strings:
        return result

    for elem in axml_mod.iter_start_elements(axml, pos):
        elem_name = pool.get(elem.name_index)

        # Attributes are addressable two ways: by resource ID (android:* attrs)
        # and by pool index (everything else, e.g. `package` on <manifest>).
        by_res_id: dict[int, tuple[int, str]] = {}
        by_name: dict[int, tuple[int, str]] = {}
        for attr in elem.attributes:
            raw_str = (
                pool.get(attr.raw_value_index) if attr.value_type == axml_mod.TYPE_STRING else ""
            )
            value = (attr.value_data, raw_str)
            by_res_id[pool.res_id(attr.name_index)] = value
            by_name[attr.name_index] = value

        def _str_val(rid: int, *, _by_res_id=by_res_id) -> str:
            v = _by_res_id.get(rid)
            return (v[1] or pool.get(v[0])) if v else ""

        def _int_val(rid: int, *, _by_res_id=by_res_id) -> int | None:
            v = _by_res_id.get(rid)
            return v[0] if v else None

        def _named_val(name: str, *, _by_name=by_name) -> str:
            """Look up an attribute by literal name.

            Attributes outside the ``android`` namespace — ``package`` on
            ``<manifest>``, most notably — carry no resource ID, so the string
            pool is the only way to find them.
            """
            idx = pool.index_of(name)
            if idx is None:
                return ""
            v = _by_name.get(idx)
            return v[1] if v and v[1] else ""

        if elem_name == "manifest":
            result["package_name"] = _named_val("package") or _str_val(0)
            result["version_code"] = _int_val(RES_VERSION_CODE)
            result["version_name"] = _str_val(RES_VERSION_NAME)
        elif elem_name == "uses-sdk":
            result["min_sdk"] = _int_val(RES_MIN_SDK)
            result["target_sdk"] = _int_val(RES_TARGET_SDK)
        elif elem_name == "uses-permission":
            perm = _str_val(RES_NAME) or _named_val("name")
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

    info["dex_files"] = sorted(n for n in names if DEX_NAME_RE.match(n))
    info["dex_count"] = len(info["dex_files"])
    info["file_size_bytes"] = os.path.getsize(apk_path)
    info["entry_count"] = len(names)

    if not info["package_name"]:
        info["package_name"] = fallback_package_name(axml)

    return info
