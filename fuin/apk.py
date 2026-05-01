"""
APK repack utilities.
Handles: inject encrypted DEX + key, repack, zipalign, apksigner.
"""

import io
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ENCRYPTED_DEX_ASSET = "assets/encrypted.dex"


def _find_build_tool(name: str) -> str:
    """Locate an Android build-tool binary (zipalign, apksigner, etc.).

    Search order:
      1. PATH (shutil.which)
      2. $ANDROID_HOME/build-tools/<latest>/
      3. ~/android-sdk/build-tools/<latest>/  (fuin default install location)
    """
    found = shutil.which(name)
    if found:
        return found

    for sdk_root in filter(
        None, [os.environ.get("ANDROID_HOME"), str(Path.home() / "android-sdk")]
    ):
        bt_root = Path(sdk_root) / "build-tools"
        if bt_root.is_dir():
            for version_dir in sorted(bt_root.iterdir(), reverse=True):
                candidate = version_dir / name
                if candidate.is_file():
                    return str(candidate)

    return name  # fall back to bare name so the subprocess error is informative


KEY_ASSET = "assets/key.bin"
ORIGINAL_APP_META_ASSET = "assets/original_app_class.txt"


def inject_encrypted_dex(
    apk_path: str,
    encrypted_dex: bytes,
    key: bytes,
    original_app_class: str,
    output_path: str,
    stub_dex: bytes | None = None,
) -> None:
    """
    Inject into the APK:
      classes.dex                   ← stub DEX (StubApplication)
      assets/encrypted.dex          ← AES-GCM encrypted original classes.dex
      assets/key.bin                ← AES key bytes
      assets/original_app_class.txt ← original Application class name
    """
    if stub_dex is None:
        from fuin.stub_dex import get_stub_dex

        stub_dex = get_stub_dex()

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            if item.filename == "classes.dex":
                continue
            zout.writestr(item, zin.read(item.filename))

        zout.writestr("classes.dex", stub_dex)
        zout.writestr(ENCRYPTED_DEX_ASSET, encrypted_dex)
        zout.writestr(KEY_ASSET, key)
        zout.writestr(ORIGINAL_APP_META_ASSET, original_app_class.encode())

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())


def zipalign(apk_path: str, output_path: str) -> None:
    zipalign_bin = _find_build_tool("zipalign")
    result = subprocess.run(
        [zipalign_bin, "-f", "-v", "4", apk_path, output_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"zipalign failed:\n{result.stderr}")


def sign_apk(apk_path: str, keystore: str, key_alias: str, store_pass: str, key_pass: str) -> None:
    apksigner_bin = _find_build_tool("apksigner")
    result = subprocess.run(
        [
            apksigner_bin,
            "sign",
            "--ks",
            keystore,
            "--ks-key-alias",
            key_alias,
            "--ks-pass",
            f"pass:{store_pass}",
            "--key-pass",
            f"pass:{key_pass}",
            apk_path,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"apksigner failed:\n{result.stderr}")


def create_debug_keystore(keystore_path: str) -> dict:
    """Create a temporary debug keystore using the cryptography library (no keytool required)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

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
