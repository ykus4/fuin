"""DEX string-obfuscation tests.

string_encrypt.py was never exercised: no test enabled encrypt_strings, so
neither the XOR pass nor the DEX header repair had any coverage.
"""

import hashlib
import struct
import zlib

import pytest

from fuin.encryption.dex_strings import DEX_MAGIC, _derive_xor_key, encrypt_dex_strings

HEADER_SIZE = 112
STRING_IDS_SIZE_OFF = 56
STRING_IDS_OFF_OFF = 60
DATA_SIZE_OFF = 104
DATA_OFF_OFF = 108


def make_dex(payload: bytes = b"hello world, a string constant") -> bytes:
    """Build a DEX-shaped buffer with the header fields the encryptor reads."""
    data_off = HEADER_SIZE
    dex = bytearray(HEADER_SIZE + len(payload))
    dex[0:8] = DEX_MAGIC + b"035\x00"
    struct.pack_into("<I", dex, STRING_IDS_SIZE_OFF, 1)
    struct.pack_into("<I", dex, STRING_IDS_OFF_OFF, HEADER_SIZE)
    struct.pack_into("<I", dex, DATA_SIZE_OFF, len(payload))
    struct.pack_into("<I", dex, DATA_OFF_OFF, data_off)
    dex[data_off:] = payload
    return bytes(dex)


KEY = b"\x01" * 32


def test_obfuscates_the_data_section():
    payload = b"a secret string constant"
    dex = make_dex(payload)

    out, xor_key = encrypt_dex_strings(dex, KEY)

    assert len(out) == len(dex)
    assert payload not in out
    assert len(xor_key) == 256


def test_header_before_the_data_section_is_untouched():
    dex = make_dex()
    out, _ = encrypt_dex_strings(dex, KEY)
    # Bytes 0..8 (magic) and the section table survive; 8..32 are the
    # recomputed checksum and signature.
    assert out[:8] == dex[:8]
    assert out[32:HEADER_SIZE] == dex[32:HEADER_SIZE]


def test_roundtrip_with_the_same_key_recovers_the_original():
    """The stub XORs the same key back at runtime, so this must be an involution."""
    payload = b"round-trip me please, all of me"
    dex = make_dex(payload)

    out, xor_key = encrypt_dex_strings(dex, KEY)

    restored = bytearray(out)
    for i in range(HEADER_SIZE, len(restored)):
        restored[i] ^= xor_key[(i - HEADER_SIZE) % len(xor_key)]
    assert bytes(restored[HEADER_SIZE:]) == payload


def test_checksum_and_signature_are_repaired():
    """A DEX with a stale checksum is rejected by the runtime, so this matters."""
    out, _ = encrypt_dex_strings(make_dex(), KEY)

    assert out[12:32] == hashlib.sha1(out[32:]).digest()
    assert struct.unpack_from("<I", out, 8)[0] == zlib.adler32(out[12:]) & 0xFFFFFFFF


def test_key_derivation_is_deterministic_and_key_dependent():
    assert _derive_xor_key(KEY) == _derive_xor_key(KEY)
    assert _derive_xor_key(KEY) != _derive_xor_key(b"\x02" * 32)
    assert len(_derive_xor_key(KEY, length=100)) == 100


def test_different_keys_produce_different_output():
    dex = make_dex()
    a, _ = encrypt_dex_strings(dex, KEY)
    b, _ = encrypt_dex_strings(dex, b"\x99" * 32)
    assert a != b


def test_non_dex_input_is_returned_unchanged():
    blob = b"this is definitely not a dex file"
    out, xor_key = encrypt_dex_strings(blob, KEY)
    assert out == blob
    assert xor_key == b""


@pytest.mark.parametrize("size", [0, 8, 44, 63, 64, 107, 111])
def test_truncated_dex_headers_do_not_crash(size):
    """Header fields are read at byte offsets up to 112; short buffers must not raise."""
    truncated = make_dex()[:size]
    if not truncated.startswith(DEX_MAGIC[:3]):
        pytest.skip("magic itself is truncated away")
    out, _ = encrypt_dex_strings(truncated, KEY)
    assert out == truncated
