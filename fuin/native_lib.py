"""
Native library (.so) encryption.

Extracts .so files from lib/<ABI>/, encrypts them with AES-256-GCM,
and prepares them for injection into the APK as encrypted assets.
"""

import json
import zipfile

from fuin.crypto import encrypt_dex as encrypt_blob


def encrypt_native_libs(
    apk_path: str,
    key: bytes,
    *,
    exclude_files: set[str] | None = None,
) -> dict | None:
    """Encrypt native libraries found in the APK.

    Returns a dict with:
      - encrypted_libs: dict[filename, encrypted_bytes]
      - manifest: bytes (JSON metadata for runtime decryption)
      - strip_patterns: list of regex patterns to strip from original APK

    Returns None if no native libraries are found.
    """
    exclude_files = exclude_files or set()
    libs: dict[str, bytes] = {}

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                if name in exclude_files:
                    continue
                libs[name] = z.read(name)

    if not libs:
        return None

    encrypted_libs: dict[str, bytes] = {}
    manifest_entries = []

    for original_path, data in libs.items():
        # Use a safe filename for the encrypted version
        safe_name = original_path.replace("/", "_") + ".enc"
        encrypted_libs[safe_name] = encrypt_blob(data, key)
        manifest_entries.append(
            {
                "original_path": original_path,
                "encrypted_name": safe_name,
                "size": len(data),
            }
        )

    manifest = json.dumps(manifest_entries).encode()

    return {
        "encrypted_libs": encrypted_libs,
        "manifest": manifest,
        "strip_patterns": [r"^lib/.*\.so$"],
    }
