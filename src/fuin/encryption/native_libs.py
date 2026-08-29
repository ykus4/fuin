"""Native library (.so) encryption.

Extracts .so files from lib/<ABI>/, encrypts them with AES-256-GCM, and
prepares them for injection into the APK as encrypted assets.
"""

import json

from fuin.contract import is_native_lib
from fuin.encryption.aes import encrypt_blob
from fuin.encryption.entries import EncryptedEntries, read_matching_entries


def encrypt_native_libs(
    apk_path: str,
    key: bytes,
    *,
    exclude_files: set[str] | None = None,
) -> EncryptedEntries | None:
    """Encrypt native libraries found in the APK. Returns None if none found.

    Only the libraries that were actually encrypted are stripped. Returning a
    blanket ``lib/**/*.so`` strip pattern also deleted every excluded library,
    which shipped an APK missing code nothing could load.
    """
    exclude_files = exclude_files or set()
    libs = read_matching_entries(apk_path, is_native_lib, exclude_files)
    if not libs:
        return None

    blobs: dict[str, bytes] = {}
    manifest_entries = []

    for original_path, data in libs.items():
        safe_name = original_path.replace("/", "_") + ".enc"
        blobs[safe_name] = encrypt_blob(data, key)
        manifest_entries.append(
            {
                "original_path": original_path,
                "encrypted_name": safe_name,
                "size": len(data),
            }
        )

    return EncryptedEntries(
        blobs=blobs,
        index=json.dumps(manifest_entries).encode(),
        strip_names=frozenset(libs),
    )
