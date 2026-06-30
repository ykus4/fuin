"""Native library (.so) encryption.

Extracts .so files from lib/<ABI>/, encrypts them with AES-256-GCM, and
prepares them for injection into the APK as encrypted assets.
"""

import json
import zipfile

from fuin.crypto import encrypt_blob


def encrypt_native_libs(
    apk_path: str,
    key: bytes,
    *,
    exclude_files: set[str] | None = None,
) -> dict | None:
    """Encrypt native libraries found in the APK. Returns None if none found."""
    exclude_files = exclude_files or set()
    libs: dict[str, bytes] = {}

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.startswith("lib/") and name.endswith(".so") and name not in exclude_files:
                libs[name] = z.read(name)

    if not libs:
        return None

    encrypted_libs: dict[str, bytes] = {}
    manifest_entries = []

    for original_path, data in libs.items():
        safe_name = original_path.replace("/", "_") + ".enc"
        encrypted_libs[safe_name] = encrypt_blob(data, key)
        manifest_entries.append(
            {
                "original_path": original_path,
                "encrypted_name": safe_name,
                "size": len(data),
            }
        )

    return {
        "encrypted_libs": encrypted_libs,
        "manifest": json.dumps(manifest_entries).encode(),
        "strip_patterns": [r"^lib/.*\.so$"],
    }
