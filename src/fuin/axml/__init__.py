"""Android Binary XML: reading, patching and manifest inspection.

Purely byte-level — nothing in this package opens a ZIP or touches the
filesystem. The APK-level wrappers live in :mod:`fuin.apk`.
"""

from fuin.axml.constants import ANDROID_NS, MANIFEST_NAME
from fuin.axml.info import empty_manifest_info, parse_manifest
from fuin.axml.patcher import patch_axml
from fuin.axml.reader import (
    Attribute,
    StartElement,
    StringPool,
    body_offset,
    decode_pool_string,
    encode_pool_string_utf16,
    iter_start_elements,
    read_string_pool,
)

__all__ = [
    "ANDROID_NS",
    "MANIFEST_NAME",
    "Attribute",
    "StartElement",
    "StringPool",
    "body_offset",
    "decode_pool_string",
    "empty_manifest_info",
    "encode_pool_string_utf16",
    "iter_start_elements",
    "parse_manifest",
    "patch_axml",
    "read_string_pool",
]
