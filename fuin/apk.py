"""
APK repack utilities.
Handles: inject encrypted DEX + key, repack, zipalign, apksigner.
"""

import io
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

ENCRYPTED_DEX_ASSET = "assets/encrypted.dex"
# Extra DEX files (classes2.dex, classes3.dex, ...) are bundled into a ZIP and stored here
ENCRYPTED_EXTRA_DEX_ASSET = "assets/encrypted_extra.dex"
CERT_FINGERPRINT_ASSET = "assets/cert_fingerprint.bin"
SECURITY_POLICY_ASSET = "assets/security_policy.json"
NATIVE_LIB_MANIFEST_ASSET = "assets/native_lib_manifest.json"
ENCRYPTED_LIBS_PREFIX = "assets/encrypted_libs/"
ENCRYPTED_RES_PREFIX = "assets/encrypted_res/"
RES_MAP_ASSET = "assets/res_map.json"


def _find_build_tool(name: str) -> str:
    """Locate an Android build-tool binary. Checks PATH then $ANDROID_HOME/build-tools/."""
    found = shutil.which(name)
    if found:
        return found

    sdk_root = os.environ.get("ANDROID_HOME")
    if sdk_root:
        bt_root = Path(sdk_root) / "build-tools"
        if bt_root.is_dir():
            for version_dir in sorted(bt_root.iterdir(), reverse=True):
                candidate = version_dir / name
                if candidate.is_file():
                    return str(candidate)

    return name


KEY_ASSET = "assets/key.bin"
ORIGINAL_APP_META_ASSET = "assets/original_app_class.txt"


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
    """
    Inject into the APK:
      classes.dex                   <- stub DEX (StubApplication)
      assets/encrypted.dex          <- AES-GCM encrypted original classes.dex
      assets/encrypted_extra.dex    <- ZIP of encrypted classes2.dex, classes3.dex, ... (if any)
      assets/key.bin                <- AES key bytes (same key for all DEX files)
      assets/original_app_class.txt <- original Application class name
      assets/cert_fingerprint.bin   <- signing cert SHA-256 (anti-tamper)
      assets/security_policy.json   <- runtime security policy (root/emulator detection)
      assets/encrypted_libs/*       <- encrypted native libraries
      assets/native_lib_manifest.json <- native lib metadata
      assets/encrypted_res/*        <- encrypted resources/assets
      assets/res_map.json           <- resource mapping
    """
    if stub_dex is None:
        from fuin.stub_dex import get_stub_dex

        stub_dex = get_stub_dex()

    # DEX filenames to strip from the original APK (classes.dex + classesN.dex)
    dex_pattern = re.compile(r"^classes\d*\.dex$")

    # Patterns to strip (e.g. lib/**/*.so when encrypting native libs)
    _strip_patterns = [re.compile(p) for p in (strip_patterns or [])]

    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            if dex_pattern.match(item.filename):
                continue
            if any(p.match(item.filename) for p in _strip_patterns):
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
            zout.writestr("assets/string_key.bin", string_key)

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
    """Sign an APK with v1 + v2 signatures.

    Tries the apksigner binary first (gives v2/v3). If unavailable or Java is
    missing, falls back to pure-Python v1 + v2.
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
        if result.returncode == 0:
            return
        if "Java Runtime" not in result.stderr and "java" not in result.stderr.lower():
            raise RuntimeError(f"apksigner failed:\n{result.stderr}")

    # Pure-Python path: v1 + v2
    _sign_apk_v1(apk_path, keystore, key_alias, store_pass)
    _sign_apk_v2(apk_path, keystore, store_pass)


def verify_apk_signature(apk_path: str) -> bool:
    """Verify the APK signature with apksigner when Android build-tools are available."""
    apksigner_bin = _find_build_tool("apksigner")
    if not Path(apksigner_bin).is_file():
        return False

    result = subprocess.run(
        [apksigner_bin, "verify", "--verbose", apk_path],
        capture_output=True,
        text=True,
        env=_apksigner_env(),
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"apksigner verify failed:\n{details}")
    return True


def _apksigner_env() -> dict:
    """Return the current environment for apksigner subprocess."""
    return os.environ.copy()


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


def _sign_apk_v2(apk_path: str, keystore_path: str, password: str) -> None:
    """
    Add APK Signature Scheme v2 block to the APK.

    APK v2 structure:
      [ZIP entries]  [APK Signing Block]  [Central Directory]  [EOCD]

    The signing block is inserted between the last local file entry and the
    central directory. EOCD's CD offset is updated accordingly.

    See: https://source.android.com/docs/security/features/apksigning/v2
    """
    import hashlib
    import struct as _struct

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import pkcs12

    p12_data = Path(keystore_path).read_bytes()
    private_key, cert, _ = pkcs12.load_key_and_certificates(p12_data, password.encode())

    apk_data = bytearray(Path(apk_path).read_bytes())

    # Locate Central Directory and EOCD
    eocd_offset = _find_eocd(apk_data)
    if eocd_offset is None:
        raise RuntimeError("Cannot find EOCD in APK — not a valid ZIP")

    cd_offset = _struct.unpack_from("<I", apk_data, eocd_offset + 16)[0]
    cd_size = _struct.unpack_from("<I", apk_data, eocd_offset + 12)[0]

    # The "signed data" sections for v2:
    #   Section 1: everything before CD  (bytes 0..cd_offset)
    #   Section 2: Central Directory
    #   Section 3: EOCD with CD offset zeroed

    section1 = bytes(apk_data[:cd_offset])
    section2 = bytes(apk_data[cd_offset : cd_offset + cd_size])
    eocd_for_sig = bytearray(apk_data[eocd_offset:])
    _struct.pack_into("<I", eocd_for_sig, 16, 0)  # zero out CD offset
    section3 = bytes(eocd_for_sig)

    def _digest_section(data: bytes) -> bytes:
        # Each section is split into 1MB chunks, each chunk prefixed with 0xa5 + u32 length
        CHUNK = 1 << 20
        chunks = []
        for i in range(0, max(1, len(data)), CHUNK):
            chunk = data[i : i + CHUNK]
            prefix = b"\xa5" + _struct.pack("<I", len(chunk))
            chunks.append(hashlib.sha256(prefix + chunk).digest())
        top_prefix = b"\x5a" + _struct.pack("<I", len(chunks))
        return hashlib.sha256(top_prefix + b"".join(chunks)).digest()

    d1 = _digest_section(section1)
    d2 = _digest_section(section2)
    d3 = _digest_section(section3)

    # Combined digest over all three section digests
    top = b"\x5a" + _struct.pack("<I", 3) + d1 + d2 + d3
    content_digest = hashlib.sha256(top).digest()

    # signed data blob (v2 signer)
    # digest: algorithm ID (0x0103 = SHA-256 with RSA PKCS1v15) + digest bytes
    alg_id = 0x0103  # RSASSA-PKCS1-v1_5 with SHA2-256
    digest_entry = _struct.pack("<II", alg_id, len(content_digest)) + content_digest
    digests_blob = _struct.pack("<I", len(digest_entry)) + digest_entry

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    certs_blob = _struct.pack("<II", len(cert_der), len(cert_der)) + cert_der

    # signed data = length-prefixed(digests) + length-prefixed(certs) + length-prefixed(attrs=empty)
    attrs_blob = _struct.pack("<I", 0)
    signed_data = (
        _struct.pack("<I", len(digests_blob))
        + digests_blob
        + _struct.pack("<I", len(certs_blob))
        + certs_blob
        + _struct.pack("<I", len(attrs_blob))
        + attrs_blob
    )

    # signature over signed_data
    sig_bytes = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    sig_entry = _struct.pack("<II", alg_id, len(sig_bytes)) + sig_bytes
    sigs_blob = _struct.pack("<II", len(sig_entry), len(sig_entry)) + sig_entry

    pub_key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # signer block = length-prefixed(signed_data) + length-prefixed(sigs) + length-prefixed(pubkey)
    signer = (
        _struct.pack("<I", len(signed_data))
        + signed_data
        + _struct.pack("<I", len(sigs_blob))
        + sigs_blob
        + _struct.pack("<I", len(pub_key_der))
        + pub_key_der
    )
    signers_blob = _struct.pack("<I", len(signer)) + signer

    # v2 signing block pair: ID=0x7109871a, value = signers_blob
    V2_BLOCK_ID = 0x7109871A
    pair = _struct.pack("<QI", len(signers_blob) + 4, V2_BLOCK_ID) + signers_blob

    # APK Signing Block: size_before + pairs + size_after + magic
    MAGIC = b"APK Sig Block 42"
    block_size = 8 + len(pair) + 8 + 16  # size_before(8) + pairs + size_after(8) + magic(16)
    signing_block = _struct.pack("<Q", block_size) + pair + _struct.pack("<Q", block_size) + MAGIC

    # Build new APK: section1 + signing_block + CD + EOCD(updated)
    new_cd_offset = cd_offset + len(signing_block)
    new_eocd = bytearray(apk_data[eocd_offset:])
    _struct.pack_into("<I", new_eocd, 16, new_cd_offset)

    new_apk = section1 + signing_block + section2 + bytes(new_eocd)
    Path(apk_path).write_bytes(new_apk)


def _find_eocd(data: bytes | bytearray) -> int | None:
    """Locate the End of Central Directory record offset."""
    import struct as _struct

    EOCD_SIG = b"PK\x05\x06"
    # Search backwards from end; comment can be up to 65535 bytes
    for i in range(len(data) - 22, max(len(data) - 65557, -1), -1):
        if data[i : i + 4] == EOCD_SIG:
            comment_len = _struct.unpack_from("<H", data, i + 20)[0]
            if i + 22 + comment_len == len(data):
                return i
    return None


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
