"""
Shared fixtures for fuin tests.
"""

import io
import struct
import zipfile

import pytest

# ---------------------------------------------------------------------------
# Minimal binary AXML helpers
# ---------------------------------------------------------------------------


def _encode_utf16(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + encoded + b"\x00\x00"


def make_axml(app_class: str = "com.example.MyApp") -> bytes:
    """
    Build a minimal valid binary AXML AndroidManifest with a single
    <application android:name="app_class"> element.
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

    # Resource map chunk (empty)
    res_map = struct.pack("<II", 0x00180002, 8)

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
            (0xFFFFFFFF, 2, 7, 0x03, 7),  # package attr, TYPE_STRING, value=pool[7]
        ],
    )
    # <application android:name="com.example.MyApp">
    #   ns=pool[0]=ANDROID_NS idx, name_attr=pool[4]="name", value=pool[5]=app_class
    app_start = start_elem(
        0,
        3,
        [
            (0, 4, 5, 0x03, 5),  # android:name, TYPE_STRING, value=pool[5]
        ],
    )
    app_end = end_elem(0, 3)
    manifest_end = end_elem(0xFFFFFFFF, 6)

    body = sp_chunk + res_map + manifest_start + app_start + app_end + manifest_end

    # File header
    file_size = 8 + len(body)
    header = struct.pack("<II", 0x00080003, file_size)
    return header + body


def make_minimal_apk(
    app_class: str = "com.example.MyApp",
    dex_content: bytes = b"dex\n035\x00" + b"\x00" * 100,
    extra_dex: dict[str, bytes] | None = None,
) -> bytes:
    """Build a minimal valid APK (ZIP) with AndroidManifest.xml + classes.dex."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", make_axml(app_class))
        z.writestr("classes.dex", dex_content)
        if extra_dex:
            for name, data in extra_dex.items():
                z.writestr(name, data)
        z.writestr("res/layout/main.xml", b"<root/>")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_apk_bytes():
    return make_minimal_apk()


@pytest.fixture
def minimal_apk(tmp_path, minimal_apk_bytes):
    path = tmp_path / "test.apk"
    path.write_bytes(minimal_apk_bytes)
    return str(path)


@pytest.fixture
def minimal_axml():
    return make_axml("com.example.MyApp")


@pytest.fixture
def debug_keystore(tmp_path):
    from fuin.apk import create_debug_keystore

    ks_path = str(tmp_path / "test.keystore")
    return create_debug_keystore(ks_path)


@pytest.fixture
def stub_dex():
    from fuin.stub_dex import get_stub_dex

    return get_stub_dex()
