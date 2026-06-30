"""AES-GCM blob encryption.

Format: [12-byte nonce][ciphertext + 16-byte tag]
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_SIZE = 32
_NONCE_SIZE = 12


def generate_key() -> bytes:
    return os.urandom(_KEY_SIZE)


def encrypt_blob(data: bytes, key: bytes) -> bytes:
    if len(key) != _KEY_SIZE:
        raise ValueError(f"key must be {_KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_blob(encrypted: bytes, key: bytes) -> bytes:
    nonce, ciphertext = encrypted[:_NONCE_SIZE], encrypted[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# --- Backwards-compatible aliases ---
encrypt_dex = encrypt_blob
decrypt_dex = decrypt_blob
