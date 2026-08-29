"""Malformed-manifest handling.

AndroidManifest.xml comes out of an APK a stranger uploaded, so every field in
it is attacker-controlled. These are the cases the parser has to survive
without raising, hanging, or allocating unboundedly — none of which the
happy-path tests exercise.
"""

import struct

import pytest

from fuin.axml.info import parse_manifest
from fuin.axml.patcher import patch_axml
from fuin.axml.reader import read_string_pool
from fuin.contract import STUB_CLASS
from tests.fixtures import make_axml

# The string-pool header sits at offset 8; string_count is its third u32.
_STRING_COUNT_OFFSET = 8 + 8


def with_string_count(count: int) -> bytes:
    data = bytearray(make_axml())
    struct.pack_into("<I", data, _STRING_COUNT_OFFSET, count)
    return bytes(data)


@pytest.mark.parametrize("count", [1_000_000, 0x7FFFFFFF, 0xFFFFFFFF])
def test_string_count_is_bounded_by_the_buffer(count):
    """A u32 count is not a promise that the offsets are there.

    Trusting it turns a few hundred bytes of upload into gigabytes of
    placeholder strings — a memory bomb reachable from POST /pack.
    """
    assert read_string_pool(with_string_count(count), 8) is None


@pytest.mark.parametrize("count", [1_000_000, 0xFFFFFFFF])
def test_oversized_string_count_leaves_the_manifest_alone(count):
    data = with_string_count(count)

    patched, found = patch_axml(data, None)

    assert patched == data
    assert found == ""


@pytest.mark.parametrize("length", range(0, 64))
def test_truncated_manifest_never_raises(length):
    """Every prefix of a real manifest must return, not raise.

    `patch_axml` previously read the chunk type back out of the buffer to log
    that the buffer was too short, and blew up doing it.
    """
    patched, found = patch_axml(make_axml()[:length], None)

    assert isinstance(patched, bytes)
    assert isinstance(found, str)


def test_truncated_manifest_parses_to_something_usable():
    info = parse_manifest(make_axml()[:40])

    assert isinstance(info, dict)
    assert "package_name" in info


def test_garbage_is_not_mistaken_for_a_manifest():
    patched, found = patch_axml(b"\x00" * 512, None)

    assert patched == b"\x00" * 512
    assert found == ""


def test_fallback_refuses_a_length_changing_substitution():
    """AXML offsets are absolute, so a resize corrupts every later chunk.

    Returning a non-empty class name here told strict mode the patch worked and
    shipped an APK whose manifest no longer parses.
    """
    short_class = "a.B"
    assert len(short_class) != len(STUB_CLASS)
    data = b"HEAD" + short_class.encode("utf-16-le") + b"TAIL"

    patched, found = patch_axml(data, short_class)

    assert patched == data
    assert found == ""


def test_round_trip_keeps_the_manifest_parseable():
    """The patched pool must still decode — offsets and sizes recomputed."""
    original = make_axml("com.example.MyApp")

    patched, found = patch_axml(original, None)

    assert found == "com.example.MyApp"
    info = parse_manifest(patched)
    assert info["package_name"] == "com.example.test"
    # The header's file-size field has to track the resized pool.
    assert struct.unpack_from("<I", patched, 4)[0] == len(patched)


@pytest.mark.parametrize(
    "app_class",
    ["a.b.Shorter", "com.example.MyApp", "com.example.a.very.much.longer.ApplicationClass"],
)
def test_round_trip_for_any_class_name_length(app_class):
    patched, found = patch_axml(make_axml(app_class), None)

    assert found == app_class
    assert struct.unpack_from("<I", patched, 4)[0] == len(patched)
    assert STUB_CLASS.encode("utf-16-le") in patched
    assert parse_manifest(patched)["package_name"] == "com.example.test"
