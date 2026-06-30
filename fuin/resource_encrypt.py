"""Resource/asset encryption.

Encrypts user assets (files in assets/ that are not fuin-internal) so they
cannot be extracted from the APK without decryption.
"""

import hashlib
import json
import re
import zipfile

from fuin._constants import (
    ENCRYPTED_LIBS_PREFIX,
    ENCRYPTED_RES_PREFIX,
    FUIN_INTERNAL_ASSETS,
)
from fuin.crypto import encrypt_blob


def encrypt_resources(
    apk_path: str,
    key: bytes,
    *,
    exclude_files: set[str] | None = None,
) -> dict | None:
    """Encrypt user-facing assets found in the APK.

    Only encrypts files under assets/ that are NOT fuin-internal. Compiled
    resources (res/, resources.arsc) are intentionally left alone.

    Returns None if no encryptable assets are found.
    """
    exclude_files = exclude_files or set()
    assets: dict[str, bytes] = {}

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if not name.startswith("assets/"):
                continue
            if name in FUIN_INTERNAL_ASSETS:
                continue
            if name.startswith(ENCRYPTED_LIBS_PREFIX) or name.startswith(ENCRYPTED_RES_PREFIX):
                continue
            if name in exclude_files:
                continue
            assets[name] = z.read(name)

    if not assets:
        return None

    encrypted_resources: dict[str, bytes] = {}
    res_map_entries: dict[str, str] = {}

    for original_path, data in assets.items():
        # SHA-256 hash as encrypted filename to avoid path traversal issues
        name_hash = hashlib.sha256(original_path.encode()).hexdigest()[:16]
        encrypted_name = f"{name_hash}.enc"
        encrypted_resources[encrypted_name] = encrypt_blob(data, key)
        res_map_entries[original_path] = encrypted_name

    res_map = json.dumps(res_map_entries).encode()
    strip_patterns = [f"^{re.escape(p)}$" for p in assets.keys()]

    return {
        "encrypted_resources": encrypted_resources,
        "res_map": res_map,
        "strip_patterns": strip_patterns,
    }
