"""APK repack utilities: inject encrypted DEX + assets, build debug keystore.

Signing and alignment have moved to :mod:`fuin.signing` and :mod:`fuin.zipalign`.
This module re-exports them for backwards compatibility.
"""

import datetime
import io
import re
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from fuin._constants import (
    CERT_FINGERPRINT_ASSET,
    ENCRYPTED_DEX_ASSET,
    ENCRYPTED_EXTRA_DEX_ASSET,
    ENCRYPTED_LIBS_PREFIX,
    ENCRYPTED_RES_PREFIX,
    KEY_ASSET,
    NATIVE_LIB_MANIFEST_ASSET,
    ORIGINAL_APP_META_ASSET,
    RES_MAP_ASSET,
    SECURITY_POLICY_ASSET,
    STRING_KEY_ASSET,
)

# Re-export so existing imports of `from fuin.apk import sign_apk, zipalign, ...` keep working.
from fuin.signing import sign_apk, verify_apk_signature  # noqa: F401
from fuin.zipalign import zipalign  # noqa: F401


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

    dex_pattern = re.compile(r"^classes\d*\.dex$")
    strip_res = [re.compile(p) for p in (strip_patterns or [])]

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            if dex_pattern.match(item.filename):
                continue
            if any(p.match(item.filename) for p in strip_res):
                continue
            zout.writestr(item, zin.read(item.filename))

        zout.writestr("classes.dex", stub_dex)
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


def create_debug_keystore(keystore_path: str) -> dict:
    """Create a temporary PKCS12 debug keystore (no keytool required)."""
    alias = "fuin_debug"
    password = "android"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Fuin Debug"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fuin"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    p12 = pkcs12.serialize_key_and_certificates(
        name=alias.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    Path(keystore_path).write_bytes(p12)
    return {"keystore": keystore_path, "alias": alias, "store_pass": password, "key_pass": password}
