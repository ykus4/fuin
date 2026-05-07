"""
DEX string encryption.

Encrypts string constants in DEX files to resist static analysis.
Uses a XOR-based obfuscation on the string data section of the DEX file.

Approach:
  - Parse the DEX header to locate the string data section
  - XOR all string data bytes with a derived key
  - Store the XOR key in assets/string_key.bin
  - At runtime, the StringDecryptor patches the string data back before class loading

This approach avoids instruction rewriting (which would require offset recalculation)
and instead operates on the raw string bytes in the DEX data section.
"""

import hashlib
import struct

DEX_MAGIC = b"dex\n"
STRING_KEY_ASSET = "assets/string_key.bin"


def encrypt_dex_strings(dex_data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt string constants in a DEX file using XOR obfuscation.

    Args:
        dex_data: Raw DEX file bytes
        key: Master AES key (used to derive XOR key)

    Returns:
        (obfuscated_dex, xor_key) — the modified DEX and the 32-byte XOR key
    """
    if not dex_data[:4].startswith(DEX_MAGIC[:3]):
        # Not a valid DEX, return unchanged
        return dex_data, b""

    # Derive a 256-byte XOR key from the master key
    xor_key = _derive_xor_key(key)

    # Parse DEX header to find string data section bounds
    string_ids_off, string_ids_size = _get_string_ids(dex_data)
    if string_ids_size == 0:
        return dex_data, xor_key

    # Find the range of string data in the DEX
    data_off, data_size = _get_data_section(dex_data)
    if data_size == 0:
        return dex_data, xor_key

    # XOR the string data section
    result = bytearray(dex_data)
    key_len = len(xor_key)

    for i in range(data_off, min(data_off + data_size, len(result))):
        result[i] ^= xor_key[(i - data_off) % key_len]

    # Fix the DEX checksum and signature
    _fix_dex_header(result)

    return bytes(result), xor_key


def _derive_xor_key(master_key: bytes, length: int = 256) -> bytes:
    """Derive a repeating XOR key from the master key using SHA-256 chaining."""
    derived = b""
    seed = master_key
    while len(derived) < length:
        seed = hashlib.sha256(seed).digest()
        derived += seed
    return derived[:length]


def _get_string_ids(dex_data: bytes) -> tuple[int, int]:
    """Get string IDs table offset and count from DEX header."""
    if len(dex_data) < 44:
        return 0, 0
    string_ids_size = struct.unpack_from("<I", dex_data, 56)[0]
    string_ids_off = struct.unpack_from("<I", dex_data, 60)[0]
    return string_ids_off, string_ids_size


def _get_data_section(dex_data: bytes) -> tuple[int, int]:
    """Get the data section offset and size from DEX header."""
    if len(dex_data) < 108:
        return 0, 0
    data_size = struct.unpack_from("<I", dex_data, 104)[0]
    data_off = struct.unpack_from("<I", dex_data, 108)[0]
    return data_off, data_size


def _fix_dex_header(dex: bytearray) -> None:
    """Recalculate DEX file checksum and SHA-1 signature."""
    # SHA-1 signature covers bytes 32..EOF
    import hashlib as _hashlib

    sha1 = _hashlib.sha1(dex[32:]).digest()
    dex[12:32] = sha1

    # Adler32 checksum covers bytes 12..EOF
    import zlib

    checksum = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", dex, 8, checksum)
