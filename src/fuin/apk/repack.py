"""APK-level rewriting: patch the manifest, inject the stub DEX and fuin assets.

This is the layer that owns ZIP I/O. The byte-level AXML work it delegates to
:mod:`fuin.axml`.
"""

import io
import zipfile
from dataclasses import dataclass, field
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


@dataclass(frozen=True, slots=True)
class InjectedAssets:
    """Everything the packer hands to the stub, beyond the encrypted DEX.

    Each field is optional because each protection layer is optional. Grouping
    them keeps :func:`inject_encrypted_dex` from taking fourteen positional
    arguments whose order only the packer knew.
    """

    stub_dex: bytes
    encrypted_extra_dex: bytes | None = None
    cert_fingerprint: bytes | None = None
    security_policy: bytes | None = None
    string_key: bytes | None = None

    encrypted_libs: dict[str, bytes] = field(default_factory=dict)
    native_lib_manifest: bytes | None = None

    encrypted_resources: dict[str, bytes] = field(default_factory=dict)
    res_map: bytes | None = None

    # Original entry names that are now shipped encrypted and must be dropped.
    strip_names: frozenset[str] = frozenset()


def inject_encrypted_dex(
    apk_path: str,
    encrypted_dex: bytes,
    key: bytes,
    original_app_class: str,
    output_path: str,
    assets: InjectedAssets,
) -> None:
    """Repack the APK: replace classes.dex with the stub, embed all fuin assets."""

    def _replaced(name: str) -> bool:
        # DEX files are superseded by the stub; stripped entries have been
        # encrypted into assets and must not also ship in the clear.
        return name in assets.strip_names or bool(DEX_NAME_RE.match(name))

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        copy_zip_entries(zin, zout, skip=_replaced)

        zout.writestr(PRIMARY_DEX, assets.stub_dex)
        zout.writestr(ENCRYPTED_DEX_ASSET, encrypted_dex)
        zout.writestr(KEY_ASSET, key)
        zout.writestr(ORIGINAL_APP_META_ASSET, original_app_class.encode())

        for asset_name, blob in (
            (ENCRYPTED_EXTRA_DEX_ASSET, assets.encrypted_extra_dex),
            (CERT_FINGERPRINT_ASSET, assets.cert_fingerprint),
            (SECURITY_POLICY_ASSET, assets.security_policy),
            (NATIVE_LIB_MANIFEST_ASSET, assets.native_lib_manifest),
            (RES_MAP_ASSET, assets.res_map),
            (STRING_KEY_ASSET, assets.string_key),
        ):
            if blob is not None:
                zout.writestr(asset_name, blob)

        for prefix, blobs in (
            (ENCRYPTED_LIBS_PREFIX, assets.encrypted_libs),
            (ENCRYPTED_RES_PREFIX, assets.encrypted_resources),
        ):
            for name, data in blobs.items():
                zout.writestr(f"{prefix}{name}", data)

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
