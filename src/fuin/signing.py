"""APK signing — apksigner wrapper + pure-Python v1/v2 fallback.

`sign_apk()` is the public entry point. It tries the apksigner binary first
(for v2/v3 signing) and falls back to pure-Python v1 + v2 signing when the
SDK / Java are unavailable.
"""

import base64
import hashlib
import io
import struct
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs7

from fuin._constants import (
    APK_SIG_BLOCK_MAGIC,
    APK_V2_BLOCK_ID,
    ZIP_EOCD_MAGIC,
)
from fuin._utils import copy_zip_entries
from fuin.android_tools import find_build_tool, run_tool
from fuin.keystore import load_key_and_cert

_V2_ALG_RSASSA_PKCS1_SHA256 = 0x0103


def _is_meta_inf(name: str) -> bool:
    """Signature files are regenerated, never carried over."""
    return name.startswith("META-INF/")


def sign_apk(apk_path: str, keystore: str, key_alias: str, store_pass: str, key_pass: str) -> None:
    """Sign an APK with v1 + v2 signatures."""
    bin_path = find_build_tool("apksigner")
    if bin_path:
        # check=False: a missing JRE is not fatal — we fall back to the
        # pure-Python signer below. Any other failure is a real error.
        result = run_tool(
            [
                bin_path,
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
            check=False,
        )
        if result.returncode == 0:
            return
        if "Java Runtime" not in result.stderr and "java" not in result.stderr.lower():
            raise RuntimeError(f"apksigner failed:\n{result.stderr}")

    _sign_v1(apk_path, keystore, key_alias, store_pass)
    _sign_v2(apk_path, keystore, store_pass)


def verify_apk_signature(apk_path: str) -> bool:
    """Verify the APK with apksigner. Returns False if apksigner is unavailable."""
    bin_path = find_build_tool("apksigner")
    if not bin_path:
        return False

    result = run_tool([bin_path, "verify", "--verbose", apk_path], check=False)
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"apksigner verify failed:\n{details}")
    return True


# ---------------------------------------------------------------------------
# v1 (JAR) signing
# ---------------------------------------------------------------------------


def _sign_v1(apk_path: str, keystore_path: str, alias: str, password: str) -> None:
    private_key, cert = load_key_and_cert(keystore_path, password)

    with zipfile.ZipFile(apk_path, "r") as zin:
        entries = {
            info.filename: zin.read(info.filename)
            for info in zin.infolist()
            if not _is_meta_inf(info.filename)
        }

    def _b64(d: bytes) -> str:
        return base64.b64encode(d).decode()

    def _sha256(d: bytes) -> str:
        return _b64(hashlib.sha256(d).digest())

    mf_lines = ["Manifest-Version: 1.0\r\n\r\n"]
    for name, data in sorted(entries.items()):
        mf_lines.append(f"Name: {name}\r\nSHA-256-Digest: {_sha256(data)}\r\n\r\n")
    manifest = "".join(mf_lines).encode()

    mf_digest = _sha256(manifest)
    sf_lines = [
        "Signature-Version: 1.0\r\n",
        f"SHA-256-Digest-Manifest: {mf_digest}\r\n\r\n",
    ]
    for name, data in sorted(entries.items()):
        entry_text = f"Name: {name}\r\nSHA-256-Digest: {_sha256(data)}\r\n\r\n"
        sf_lines.append(f"Name: {name}\r\nSHA-256-Digest: {_sha256(entry_text.encode())}\r\n\r\n")
    sf_bytes = "".join(sf_lines).encode()

    sig_bytes = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf_bytes)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )

    alias_upper = alias.upper()
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        copy_zip_entries(zin, zout, skip=_is_meta_inf)
        zout.writestr("META-INF/MANIFEST.MF", manifest)
        zout.writestr(f"META-INF/{alias_upper}.SF", sf_bytes)
        zout.writestr(f"META-INF/{alias_upper}.RSA", sig_bytes)

    Path(apk_path).write_bytes(buf.getvalue())


# ---------------------------------------------------------------------------
# v2 signing
# https://source.android.com/docs/security/features/apksigning/v2
# ---------------------------------------------------------------------------


def _sign_v2(apk_path: str, keystore_path: str, password: str) -> None:
    private_key, cert = load_key_and_cert(keystore_path, password)

    apk_data = bytearray(Path(apk_path).read_bytes())

    eocd_offset = _find_eocd(apk_data)
    if eocd_offset is None:
        raise RuntimeError("Cannot find EOCD in APK — not a valid ZIP")

    cd_offset = struct.unpack_from("<I", apk_data, eocd_offset + 16)[0]
    cd_size = struct.unpack_from("<I", apk_data, eocd_offset + 12)[0]

    section1 = bytes(apk_data[:cd_offset])
    section2 = bytes(apk_data[cd_offset : cd_offset + cd_size])
    eocd_for_sig = bytearray(apk_data[eocd_offset:])
    struct.pack_into("<I", eocd_for_sig, 16, 0)
    section3 = bytes(eocd_for_sig)

    top = b"\x5a" + struct.pack("<I", 3)
    top += _digest_section(section1) + _digest_section(section2) + _digest_section(section3)
    content_digest = hashlib.sha256(top).digest()

    digest_entry = (
        struct.pack("<II", _V2_ALG_RSASSA_PKCS1_SHA256, len(content_digest)) + content_digest
    )
    digests_blob = struct.pack("<I", len(digest_entry)) + digest_entry

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    certs_blob = struct.pack("<II", len(cert_der), len(cert_der)) + cert_der
    attrs_blob = struct.pack("<I", 0)

    signed_data = (
        struct.pack("<I", len(digests_blob))
        + digests_blob
        + struct.pack("<I", len(certs_blob))
        + certs_blob
        + struct.pack("<I", len(attrs_blob))
        + attrs_blob
    )

    sig_bytes = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    sig_entry = struct.pack("<II", _V2_ALG_RSASSA_PKCS1_SHA256, len(sig_bytes)) + sig_bytes
    sigs_blob = struct.pack("<II", len(sig_entry), len(sig_entry)) + sig_entry

    pub_key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    signer = (
        struct.pack("<I", len(signed_data))
        + signed_data
        + struct.pack("<I", len(sigs_blob))
        + sigs_blob
        + struct.pack("<I", len(pub_key_der))
        + pub_key_der
    )
    signers_blob = struct.pack("<I", len(signer)) + signer

    pair = struct.pack("<QI", len(signers_blob) + 4, APK_V2_BLOCK_ID) + signers_blob

    # size_before(8) + pairs + size_after(8) + magic(16)
    block_size = 8 + len(pair) + 8 + 16
    signing_block = (
        struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    )

    new_cd_offset = cd_offset + len(signing_block)
    new_eocd = bytearray(apk_data[eocd_offset:])
    struct.pack_into("<I", new_eocd, 16, new_cd_offset)

    new_apk = section1 + signing_block + section2 + bytes(new_eocd)
    Path(apk_path).write_bytes(new_apk)


def _digest_section(data: bytes) -> bytes:
    """v2 section digest: 1MB chunks, each prefixed with 0xa5 + u32 length."""
    CHUNK = 1 << 20
    chunks = []
    for i in range(0, max(1, len(data)), CHUNK):
        chunk = data[i : i + CHUNK]
        prefix = b"\xa5" + struct.pack("<I", len(chunk))
        chunks.append(hashlib.sha256(prefix + chunk).digest())
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()


def _find_eocd(data: bytes | bytearray) -> int | None:
    for i in range(len(data) - 22, max(len(data) - 65557, -1), -1):
        if data[i : i + 4] == ZIP_EOCD_MAGIC:
            comment_len = struct.unpack_from("<H", data, i + 20)[0]
            if i + 22 + comment_len == len(data):
                return i
    return None
