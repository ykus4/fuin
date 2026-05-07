"""
Resource/asset encryption.

Encrypts user assets (files in assets/ that are not fuin-internal)
so they cannot be extracted from the APK without decryption.
"""

import hashlib
import json
import zipfile

from fuin.crypto import encrypt_dex as encrypt_blob

# Assets injected by fuin itself — never encrypt these
_FUIN_INTERNAL_ASSETS = {
    "assets/encrypted.dex",
    "assets/encrypted_extra.dex",
    "assets/key.bin",
    "assets/original_app_class.txt",
    "assets/cert_fingerprint.bin",
    "assets/security_policy.json",
    "assets/native_lib_manifest.json",
    "assets/res_map.json",
}


def encrypt_resources(apk_path: str, key: bytes) -> dict | None:
    """Encrypt user-facing assets found in the APK.

    Only encrypts files under assets/ that are NOT fuin-internal.
    Does NOT encrypt compiled resources (res/, resources.arsc) as those
    are accessed directly by the Android framework.

    Returns a dict with:
      - encrypted_resources: dict[filename, encrypted_bytes]
      - res_map: bytes (JSON mapping for runtime decryption)
      - strip_patterns: list of regex patterns to strip

    Returns None if no encryptable assets are found.
    """
    assets: dict[str, bytes] = {}

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if not name.startswith("assets/"):
                continue
            if name in _FUIN_INTERNAL_ASSETS:
                continue
            if name.startswith("assets/encrypted_libs/"):
                continue
            if name.startswith("assets/encrypted_res/"):
                continue
            assets[name] = z.read(name)

    if not assets:
        return None

    encrypted_resources: dict[str, bytes] = {}
    res_map_entries: dict[str, str] = {}

    for original_path, data in assets.items():
        # Use SHA-256 hash as encrypted filename to avoid path issues
        name_hash = hashlib.sha256(original_path.encode()).hexdigest()[:16]
        encrypted_name = f"{name_hash}.enc"
        encrypted_resources[encrypted_name] = encrypt_blob(data, key)
        res_map_entries[original_path] = encrypted_name

    res_map = json.dumps(res_map_entries).encode()

    # Build strip patterns for original asset paths
    strip_patterns = [f"^{_escape_regex(p)}$" for p in assets.keys()]

    return {
        "encrypted_resources": encrypted_resources,
        "res_map": res_map,
        "strip_patterns": strip_patterns,
    }


def _escape_regex(s: str) -> str:
    """Escape a string for use in a regex pattern."""
    import re

    return re.escape(s)
