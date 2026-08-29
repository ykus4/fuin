"""Manifest inspection: package name, version, permissions, component counts.

Byte-level only, like the rest of :mod:`fuin.axml`. The APK-level wrapper that
pulls the manifest out of a ZIP lives in :mod:`fuin.apk.info`.
"""

import logging

from fuin.axml import reader as axml_mod
from fuin.axml.constants import (
    RES_MIN_SDK,
    RES_NAME,
    RES_TARGET_SDK,
    RES_VERSION_CODE,
    RES_VERSION_NAME,
    TYPE_STRING,
)

log = logging.getLogger(__name__)


def empty_manifest_info() -> dict:
    """The shape :func:`parse_manifest` always returns.

    Callers index these keys unconditionally, so the failure paths have to
    return them too rather than a differently-shaped error dict.
    """
    return {
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


def parse_manifest(axml: bytes) -> dict:
    """Extract metadata from a binary AndroidManifest.xml.

    Never raises on malformed input: an unparseable manifest yields the empty
    shape rather than an exception, because the input is untrusted.
    """
    result: dict = empty_manifest_info()

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
            raw_str = pool.get(attr.raw_value_index) if attr.value_type == TYPE_STRING else ""
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
