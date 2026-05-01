import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    return os.urandom(32)


def encrypt_dex(dex_data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, dex_data, None)
    # Format: [12-byte nonce][ciphertext+16-byte tag]
    return nonce + ciphertext


def decrypt_dex(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
