"""Resource/asset encryption.

Encrypts user assets (files in assets/ that are not fuin-internal) so they
cannot be extracted from the APK without decryption.
"""

import hashlib
import json

from fuin.contract import is_user_asset
from fuin.encryption.aes import encrypt_blob
from fuin.encryption.entries import EncryptedEntries, read_matching_entries


def encrypt_resources(
    apk_path: str,
    key: bytes,
    *,
    exclude_files: set[str] | None = None,
) -> EncryptedEntries | None:
    """Encrypt user-facing assets found in the APK.

    Only encrypts files under assets/ that are NOT fuin-internal. Compiled
    resources (res/, resources.arsc) are intentionally left alone.

    Returns None if no encryptable assets are found.
    """
    exclude_files = exclude_files or set()
    assets = read_matching_entries(apk_path, is_user_asset, exclude_files)
    if not assets:
        return None

    blobs: dict[str, bytes] = {}
    res_map_entries: dict[str, str] = {}

    for original_path, data in assets.items():
        # The asset name is hashed so an entry name can never steer where the
        # blob lands. The full digest is kept: a 64-bit prefix is cheap enough
        # to collide deliberately, and a collision silently drops one asset.
        encrypted_name = hashlib.sha256(original_path.encode()).hexdigest() + ".enc"
        blobs[encrypted_name] = encrypt_blob(data, key)
        res_map_entries[original_path] = encrypted_name

    return EncryptedEntries(
        blobs=blobs,
        index=json.dumps(res_map_entries).encode(),
        strip_names=frozenset(assets),
    )
