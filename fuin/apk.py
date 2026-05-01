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
    """Align ZIP entries to 4-byte boundaries.

    Uses the zipalign binary when available; falls back to a pure-Python
    implementation so fuin works without the Android SDK installed.
    """
    zipalign_bin = _find_build_tool("zipalign")
    if Path(zipalign_bin).is_file():
        result = subprocess.run(
            [zipalign_bin, "-f", "-v", "4", apk_path, output_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"zipalign failed:\n{result.stderr}")
    else:
        _zipalign_py(apk_path, output_path)


def _zipalign_py(apk_path: str, output_path: str, alignment: int = 4) -> None:
    """Pure-Python zipalign: align stored (uncompressed) ZIP entries to `alignment` bytes."""
    import struct

    with open(apk_path, "rb") as f:
        data = f.read()

    out = bytearray()
    src = 0

    # Locate local file headers and rewrite with correct extra-field padding
    while src < len(data) - 4:
        sig = struct.unpack_from("<I", data, src)[0]
        if sig != 0x04034B50:  # local file header signature
            break

        # Parse local file header fields
        (
            _version,
            _flags,
            method,
            _mtime,
            _mdate,
            _crc,
            comp_size,
            uncomp_size,
            fname_len,
            extra_len,
        ) = struct.unpack_from("<HHHHHIIIIHH", data, src + 4)

        header_size = 30 + fname_len + extra_len
        fname = data[src + 30 : src + 30 + fname_len]
        file_data = data[src + header_size : src + header_size + comp_size]

        if method == 0:  # STORED — needs alignment
            # Calculate padding needed so file data starts at aligned offset
            future_header_base = len(out)
            future_data_start = future_header_base + 30 + fname_len
            # We'll add extra bytes to the extra field to hit alignment
            pad = (alignment - (future_data_start % alignment)) % alignment
            new_extra = data[src + 30 + fname_len : src + 30 + fname_len + extra_len]
            new_extra = new_extra + b"\x00" * pad
            new_extra_len = len(new_extra)
        else:
            new_extra = data[src + 30 + fname_len : src + 30 + fname_len + extra_len]
            new_extra_len = extra_len

        # Write updated local file header
        out += struct.pack("<I", 0x04034B50)
        out += struct.pack(
            "<HHHHHIIIIHH",
            _version,
            _flags,
            method,
            _mtime,
            _mdate,
            _crc,
            comp_size,
            uncomp_size,
            fname_len,
            new_extra_len,
        )
        out += fname
        out += new_extra
        out += file_data

        src += header_size + comp_size

    # Append everything from the central directory onwards unchanged
    out += data[src:]

    with open(output_path, "wb") as f:
        f.write(out)


def sign_apk(apk_path: str, keystore: str, key_alias: str, store_pass: str, key_pass: str) -> None:
    """Sign an APK in-place using APK Signature Scheme v2 via the apksigner binary.

    Falls back to pure-Python v1 (JAR) signing when apksigner is not available.
    """
    apksigner_bin = _find_build_tool("apksigner")
    if Path(apksigner_bin).is_file():
        env = _apksigner_env()
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
            env=env,
        )
        # apksigner is a shell script — fall back to pure-Python if Java is unavailable
        if result.returncode != 0:
            if "Java Runtime" in result.stderr or "java" in result.stderr.lower():
                _sign_apk_v1(apk_path, keystore, key_alias, store_pass)
            else:
                raise RuntimeError(f"apksigner failed:\n{result.stderr}")
    else:
        _sign_apk_v1(apk_path, keystore, key_alias, store_pass)


def _apksigner_env() -> dict:
    """Return an env dict with JAVA_HOME set to the Homebrew OpenJDK if not already set."""
    env = os.environ.copy()
    if "JAVA_HOME" not in env:
        for candidate in [
            "/opt/homebrew/opt/openjdk@17",
            "/opt/homebrew/opt/openjdk",
            "/usr/local/opt/openjdk@17",
        ]:
            if Path(candidate).is_dir():
                env["JAVA_HOME"] = candidate
                env["PATH"] = str(Path(candidate) / "bin") + ":" + env.get("PATH", "")
                break
    return env


def _sign_apk_v1(apk_path: str, keystore_path: str, alias: str, password: str) -> None:
    """Pure-Python APK v1 (JAR) signing — no apksigner / Java required.

    Writes META-INF/MANIFEST.MF, META-INF/<ALIAS>.SF, and META-INF/<ALIAS>.RSA
    into the APK ZIP in-place.
    """
    import base64
    import hashlib
    import io as _io

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

    # Load key + cert from PKCS12 keystore
    p12_data = Path(keystore_path).read_bytes()
    private_key, cert, _ = pkcs12.load_key_and_certificates(p12_data, password.encode())

    # Read all entries
    with zipfile.ZipFile(apk_path, "r") as zin:
        entries = {
            info.filename: zin.read(info.filename)
            for info in zin.infolist()
            if not info.filename.startswith("META-INF/")
        }

    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    def _sha256(data: bytes) -> str:
        return _b64(hashlib.sha256(data).digest())

    # Build MANIFEST.MF
    mf_lines = ["Manifest-Version: 1.0\r\n\r\n"]
    for name, data in sorted(entries.items()):
        digest = _sha256(data)
        entry = f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n"
        mf_lines.append(entry)
    manifest = "".join(mf_lines).encode()

    # Build <ALIAS>.SF
    mf_digest = _sha256(manifest)
    sf_lines = [
        "Signature-Version: 1.0\r\n",
        f"SHA-256-Digest-Manifest: {mf_digest}\r\n\r\n",
    ]
    for name, data in sorted(entries.items()):
        entry_text = f"Name: {name}\r\nSHA-256-Digest: {_sha256(data)}\r\n\r\n"
        sf_lines.append(f"Name: {name}\r\nSHA-256-Digest: {_sha256(entry_text.encode())}\r\n\r\n")
    sf_bytes = "".join(sf_lines).encode()

    # Build PKCS7 signature (.RSA)
    sig_bytes = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf_bytes)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )

    alias_upper = alias.upper()

    # Rewrite APK with META-INF entries
    buf = _io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for info in zin.infolist():
            if not info.filename.startswith("META-INF/"):
                zout.writestr(info, zin.read(info.filename))
        zout.writestr("META-INF/MANIFEST.MF", manifest)
        zout.writestr(f"META-INF/{alias_upper}.SF", sf_bytes)
        zout.writestr(f"META-INF/{alias_upper}.RSA", sig_bytes)

    Path(apk_path).write_bytes(buf.getvalue())


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
