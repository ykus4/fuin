import pytest
from cryptography.exceptions import InvalidTag

from fuin.crypto import decrypt_dex, encrypt_dex, generate_key


def test_generate_key_length():
    key = generate_key()
    assert len(key) == 32


def test_generate_key_is_random():
    assert generate_key() != generate_key()


def test_roundtrip():
    key = generate_key()
    plaintext = b"Hello, DEX!" * 100
    encrypted = encrypt_dex(plaintext, key)
    assert decrypt_dex(encrypted, key) == plaintext


def test_encrypted_differs_from_plaintext():
    key = generate_key()
    plaintext = b"sensitive bytecode" * 50
    encrypted = encrypt_dex(plaintext, key)
    assert plaintext not in encrypted


def test_nonce_is_prepended():
    key = generate_key()
    data = b"x" * 32
    encrypted = encrypt_dex(data, key)
    # nonce is 12 bytes, ciphertext is len(data) bytes, tag is 16 bytes
    assert len(encrypted) == 12 + len(data) + 16


def test_wrong_key_raises():
    key = generate_key()
    wrong_key = generate_key()
    encrypted = encrypt_dex(b"secret", key)
    with pytest.raises(InvalidTag):
        decrypt_dex(encrypted, wrong_key)


def test_tampered_ciphertext_raises():
    key = generate_key()
    encrypted = bytearray(encrypt_dex(b"secret data", key))
    encrypted[15] ^= 0xFF  # flip bits in ciphertext
    with pytest.raises(InvalidTag):
        decrypt_dex(bytes(encrypted), key)


def test_tampered_nonce_raises():
    key = generate_key()
    encrypted = bytearray(encrypt_dex(b"secret data", key))
    encrypted[0] ^= 0xFF  # flip bits in nonce
    with pytest.raises(InvalidTag):
        decrypt_dex(bytes(encrypted), key)


def test_large_dex():
    key = generate_key()
    plaintext = b"\xde\xad\xbe\xef" * (1024 * 256)  # 1 MB
    assert decrypt_dex(encrypt_dex(plaintext, key), key) == plaintext
