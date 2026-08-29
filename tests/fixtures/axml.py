"""Hand-rolled binary AXML builder for tests.

Deliberately independent of fuin.axml: a builder that shared the parser's
code could not catch the parser being wrong.
"""

import struct


def _encode_utf16(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + encoded + b"\x00\x00"


# Resource IDs, hardcoded rather than imported: this builder stays independent
# of fuin.axml so it can catch fuin.axml being wrong.
_RES_NAME = 0x01010003
_RES_MIN_SDK = 0x0101020C
_RES_TARGET_SDK = 0x01010270

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10


def make_axml(
    app_class: str = "com.example.MyApp",
    *,
    min_sdk: int | None = None,
    target_sdk: int | None = None,
) -> bytes:
    """
    Build a minimal valid binary AXML AndroidManifest with a single
    <application android:name="app_class"> element.

    Pass ``min_sdk``/``target_sdk`` to add a ``<uses-sdk>`` element. Those
    attributes are only addressable through the resource map, so this is what
    exercises resource-ID lookup at all.
    """
    ANDROID_NS = "http://schemas.android.com/apk/res/android"

    strings = [
        ANDROID_NS,  # 0
        "android",  # 1
        "package",  # 2
        "application",  # 3
        "name",  # 4
        app_class,  # 5
        "manifest",  # 6
        "com.example.test",  # 7
    ]
    # Parallel to the strings, by index.
    res_ids = [0, 0, 0, 0, _RES_NAME, 0, 0, 0]

    wants_uses_sdk = min_sdk is not None or target_sdk is not None
    if wants_uses_sdk:
        strings += ["uses-sdk", "minSdkVersion", "targetSdkVersion"]  # 8, 9, 10
        res_ids += [0, _RES_MIN_SDK, _RES_TARGET_SDK]

    # Build string pool
    string_blobs = [_encode_utf16(s) for s in strings]
    offsets = []
    pos = 0
    for b in string_blobs:
        offsets.append(pos)
        pos += len(b)
    strings_data = b"".join(string_blobs)

    offsets_blob = struct.pack(f"<{len(strings)}I", *offsets)
    sp_strings_start = 28 + len(strings) * 4  # header(28) + offsets
    sp_size = sp_strings_start + len(strings_data)
    # pad to 4 bytes
    if sp_size % 4:
        pad = 4 - sp_size % 4
        strings_data += b"\x00" * pad
        sp_size += pad

    sp_header = struct.pack(
        "<IIIIIII",
        0x001C0001,  # chunk type: string pool
        sp_size,
        len(strings),  # string count
        0,  # style count
        0,  # flags (UTF-16)
        sp_strings_start,
        0,  # styles start
    )
    sp_chunk = sp_header + offsets_blob + strings_data

    # Resource map chunk. The type word is u16 type + u16 header size:
    # RES_XML_RESOURCE_MAP_TYPE (0x0180) with an 8-byte header. Declaring a
    # header larger than the chunk makes real AXML parsers — apksigner's
    # included — reject the whole manifest.
    res_map = struct.pack("<II", 0x00080180, 8 + len(res_ids) * 4) + struct.pack(
        f"<{len(res_ids)}I", *res_ids
    )

    # <manifest> start element
    def start_elem(ns_idx, name_idx, attrs):
        attr_count = len(attrs)
        attr_data = b""
        for a_ns, a_name, a_raw, a_type, a_data in attrs:
            # ns(4) + name(4) + rawValue(4) + valueSize(2) + res0(1) + type(1) + data(4) = 20B
            attr_data += struct.pack("<IIIHBBI", a_ns, a_name, a_raw, 8, 0, a_type, a_data)
        # 8 (chunk header) + 16 (line+comment+ns+name) + 12 (attr info: 6 x u16) + attrs
        size = 8 + 16 + 12 + len(attr_data)
        return (
            struct.pack("<II", 0x00100102, size)
            + struct.pack("<II", 1, 0xFFFFFFFF)  # line, comment
            + struct.pack("<II", 0xFFFFFFFF, name_idx)  # ns, name
            # attrStart(2) attrSize(2) attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
            + struct.pack("<HHHHHH", 20, 20, attr_count, 0, 0, 0)
            + attr_data
        )

    def end_elem(ns_idx, name_idx):
        return (
            struct.pack("<II", 0x00100103, 24)
            + struct.pack("<II", 1, 0xFFFFFFFF)
            + struct.pack("<II", 0xFFFFFFFF, name_idx)
        )

    # <manifest package="com.example.test">
    manifest_start = start_elem(
        0xFFFFFFFF,
        6,
        [
            (0xFFFFFFFF, 2, 7, _TYPE_STRING, 7),  # package attr, value=pool[7]
        ],
    )
    # <application android:name="com.example.MyApp">
    #   ns=pool[0]=ANDROID_NS idx, name_attr=pool[4]="name", value=pool[5]=app_class
    app_start = start_elem(
        0,
        3,
        [
            (0, 4, 5, _TYPE_STRING, 5),  # android:name, value=pool[5]
        ],
    )
    app_end = end_elem(0, 3)
    manifest_end = end_elem(0xFFFFFFFF, 6)

    uses_sdk = b""
    if wants_uses_sdk:
        sdk_attrs = []
        if min_sdk is not None:
            sdk_attrs.append((0, 9, 0xFFFFFFFF, _TYPE_INT_DEC, min_sdk))
        if target_sdk is not None:
            sdk_attrs.append((0, 10, 0xFFFFFFFF, _TYPE_INT_DEC, target_sdk))
        uses_sdk = start_elem(0, 8, sdk_attrs) + end_elem(0, 8)

    body = sp_chunk + res_map + manifest_start + uses_sdk + app_start + app_end + manifest_end

    # File header
    file_size = 8 + len(body)
    header = struct.pack("<II", 0x00080003, file_size)
    return header + body
