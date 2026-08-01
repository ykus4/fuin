"""APK repack: inject the stub DEX and every fuin asset into a copy of the APK."""

import io
import re
import zipfile
from pathlib import Path

from fuin._constants import (
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
from fuin._utils import copy_zip_entries


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
        from fuin.stub_dex import get_stub_dex

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
