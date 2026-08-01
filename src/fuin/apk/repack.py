"""APK-level rewriting: patch the manifest, inject the stub DEX and fuin assets.

This is the layer that owns ZIP I/O. The byte-level AXML work it delegates to
:mod:`fuin.axml`.
"""

import io
import re
import zipfile
from pathlib import Path

from fuin.apk.zip_tools import copy_zip_entries
from fuin.axml.constants import MANIFEST_NAME
from fuin.axml.patcher import patch_axml
from fuin.contract import (
    CERT_FINGERPRINT_ASSET,
    DEX_NAME_RE,
    ENCRYPTED_DEX_ASSET,
    ENCRYPTED_EXTRA_DEX_ASSET,
    ENCRYPTED_LIBS_PREFIX,
    ENCRYPTED_RES_PREFIX,
    KEY_ASSET,
    NATIVE_LIB_MANIFEST_ASSET,
    ORIGINAL_APP_META_ASSET,
    PRIMARY_DEX,
    RES_MAP_ASSET,
    SECURITY_POLICY_ASSET,
    STRING_KEY_ASSET,
)


def inject_encrypted_dex(
    apk_path: str,
    encrypted_dex: bytes,
    key: bytes,
    original_app_class: str,
    output_path: str,
    stub_dex: bytes | None = None,
    encrypted_extra_dex: bytes | None = None,
    cert_fingerprint: bytes | None = None,
    security_policy: bytes | None = None,
    encrypted_libs: dict[str, bytes] | None = None,
    native_lib_manifest: bytes | None = None,
    encrypted_resources: dict[str, bytes] | None = None,
    res_map: bytes | None = None,
    strip_patterns: list[str] | None = None,
    string_key: bytes | None = None,
) -> None:
    """Repack the APK: replace classes.dex with stub_dex, embed all fuin assets."""
    if stub_dex is None:
        from fuin.apk.stub_dex import get_stub_dex

        stub_dex = get_stub_dex()

    strip_res = [re.compile(p) for p in (strip_patterns or [])]

    def _replaced(name: str) -> bool:
        # DEX files are superseded by the stub; stripped entries have been
        # encrypted into assets and must not also ship in the clear.
        return bool(DEX_NAME_RE.match(name)) or any(p.match(name) for p in strip_res)

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        copy_zip_entries(zin, zout, skip=_replaced)

        zout.writestr(PRIMARY_DEX, stub_dex)
        zout.writestr(ENCRYPTED_DEX_ASSET, encrypted_dex)
        zout.writestr(KEY_ASSET, key)
        zout.writestr(ORIGINAL_APP_META_ASSET, original_app_class.encode())
        if encrypted_extra_dex is not None:
            zout.writestr(ENCRYPTED_EXTRA_DEX_ASSET, encrypted_extra_dex)
        if cert_fingerprint is not None:
            zout.writestr(CERT_FINGERPRINT_ASSET, cert_fingerprint)
        if security_policy is not None:
            zout.writestr(SECURITY_POLICY_ASSET, security_policy)
        if native_lib_manifest is not None:
            zout.writestr(NATIVE_LIB_MANIFEST_ASSET, native_lib_manifest)
        if encrypted_libs:
            for name, data in encrypted_libs.items():
                zout.writestr(f"{ENCRYPTED_LIBS_PREFIX}{name}", data)
        if res_map is not None:
            zout.writestr(RES_MAP_ASSET, res_map)
        if encrypted_resources:
            for name, data in encrypted_resources.items():
                zout.writestr(f"{ENCRYPTED_RES_PREFIX}{name}", data)
        if string_key:
            zout.writestr(STRING_KEY_ASSET, string_key)

    Path(output_path).write_bytes(buf.getvalue())


def patch_manifest(apk_path: str, output_path: str, original_app_class: str | None) -> str:
    """Rewrite AndroidManifest.xml inside the APK to point at the stub.

    Returns the original application class name, or an empty string if none
    could be identified.
    """
    with zipfile.ZipFile(apk_path, "r") as zin:
        manifest_data = zin.read(MANIFEST_NAME)

    patched, found_class = patch_axml(manifest_data, original_app_class)

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        copy_zip_entries(zin, zout, replace={MANIFEST_NAME: patched})

    Path(output_path).write_bytes(buf.getvalue())
    return found_class
