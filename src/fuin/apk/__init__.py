"""APK file manipulation: repacking, manifest rewriting, signing, alignment.

This package owns ZIP I/O and the Android SDK toolchain. Byte-level AXML work
lives in :mod:`fuin.axml`.
"""

from fuin.apk.keystore import Keystore, create_debug_keystore, extract_cert_fingerprint
from fuin.apk.repack import inject_encrypted_dex, patch_manifest
from fuin.apk.signing import sign_apk, verify_apk_signature
from fuin.apk.stub_dex import get_stub_dex
from fuin.apk.tools import find_build_tool, require_build_tool, run_tool
from fuin.apk.zip_tools import copy_zip_entries, sha256_file
from fuin.apk.zipalign import zipalign

__all__ = [
    "Keystore",
    "copy_zip_entries",
    "create_debug_keystore",
    "extract_cert_fingerprint",
    "find_build_tool",
    "get_stub_dex",
    "inject_encrypted_dex",
    "patch_manifest",
    "require_build_tool",
    "run_tool",
    "sha256_file",
    "sign_apk",
    "verify_apk_signature",
    "zipalign",
]
