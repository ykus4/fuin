"""APK signing — apksigner wrapper + pure-Python v1/v2 fallback.

`sign_apk()` is the public entry point. It tries the apksigner binary first
(for v2/v3 signing) and falls back to pure-Python v1 + v2 signing when the
SDK / Java are unavailable.

The v2 layout follows
https://source.android.com/docs/security/features/apksigning/v2 — every length
prefix there is a u32, and sequences are length-prefixed *and* contain
length-prefixed items. :func:`_lp` and :func:`_seq` exist so that shape is
written once rather than open-coded per field.
"""

import base64
import hashlib
import io
import logging
import struct
import subprocess
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from fuin.apk.constants import APK_SIG_BLOCK_MAGIC, APK_V2_BLOCK_ID
from fuin.apk.keystore import load_key_and_cert
from fuin.apk.tools import find_build_tool, run_tool
from fuin.apk.zip_format import find_eocd
from fuin.apk.zip_tools import copy_zip_entries
from fuin.apk.zipalign import DEFAULT_ALIGNMENT, zipalign_file

log = logging.getLogger(__name__)

_V2_ALG_RSASSA_PKCS1_SHA256 = 0x0103

# v2 digests the APK in 1 MB chunks, each prefixed with 0xa5.
_V2_CHUNK_SIZE = 1 << 20
_V2_CHUNK_PREFIX = b"\xa5"
_V2_TOP_LEVEL_PREFIX = b"\x5a"

# Tells Android 7.0+ that a v2 signature is expected, so an attacker cannot
# strip the v2 block and have the APK accepted on its v1 signature alone.
_SF_V2_ATTRIBUTE = "X-Android-APK-Signed: 2\r\n"


def _is_meta_inf(name: str) -> bool:
    """Signature files are regenerated, never carried over."""
    return name.startswith("META-INF/")


def sign_apk(
    apk_path: str,
    keystore: str,
    key_alias: str,
    store_pass: str,
    key_pass: str,
    *,
    alignment: int = DEFAULT_ALIGNMENT,
    so_alignment: int | None = None,
) -> None:
    """Sign an APK with v1 + v2 signatures.

    The alignment arguments are only used by the pure-Python path: v1 signing
    rebuilds the archive, which drops the padding :func:`zipalign` inserted, so
    the entries have to be re-aligned before the v2 digest is taken over them.
    """
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
        if not _looks_like_missing_java(result):
            raise RuntimeError(f"apksigner failed:\n{result.stderr}")
        log.info("apksigner could not run (no JRE); using the built-in signer")

    _sign_v1(apk_path, keystore, key_alias, store_pass)
    zipalign_file(apk_path, alignment=alignment, so_alignment=so_alignment)
    _sign_v2(apk_path, keystore, store_pass)


def _looks_like_missing_java(result: subprocess.CompletedProcess[str]) -> bool:
    """Whether an apksigner failure was "no Java" rather than "bad input".

    apksigner is a shell wrapper around a JAR, so a missing JRE surfaces as a
    message from the wrapper rather than a distinct exit code. Matching on
    phrases the wrapper emits keeps a genuine signing error that merely
    mentions Java from being silently downgraded to the fallback signer.
    """
    lowered = (result.stderr or "").lower()
    return any(
        phrase in lowered
        for phrase in ("java runtime", "java_home", "java: command not found", "no such file")
    )


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
        entries = _read_signable_entries(zin)

    def _b64(d: bytes) -> str:
        return base64.b64encode(d).decode()

    def _sha256(d: bytes) -> str:
        return _b64(hashlib.sha256(d).digest())

    # Each entry's manifest stanza is digested again for the .SF, so build the
    # stanza once and reuse it rather than re-hashing the entry bytes.
    stanzas = {
        name: f"Name: {name}\r\nSHA-256-Digest: {_sha256(data)}\r\n\r\n" for name, data in entries
    }

    manifest = ("Manifest-Version: 1.0\r\n\r\n" + "".join(stanzas.values())).encode()

    sf_lines = [
        "Signature-Version: 1.0\r\n",
        _SF_V2_ATTRIBUTE,
        f"SHA-256-Digest-Manifest: {_sha256(manifest)}\r\n\r\n",
    ]
    for name, stanza in stanzas.items():
        sf_lines.append(f"Name: {name}\r\nSHA-256-Digest: {_sha256(stanza.encode())}\r\n\r\n")
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


def _read_signable_entries(zin: zipfile.ZipFile) -> list[tuple[str, bytes]]:
    """Every non-signature entry, read per physical member.

    Reading by name would silently collapse duplicate entries onto the last
    one, which is exactly the shape a masquerading APK uses — so duplicates are
    rejected rather than normalised away.
    """
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for info in zin.infolist():
        if _is_meta_inf(info.filename):
            continue
        if info.filename in seen:
            raise ValueError(f"APK contains duplicate entry {info.filename!r}; refusing to sign")
        seen.add(info.filename)
        with zin.open(info) as src:
            entries.append((info.filename, src.read()))
    entries.sort(key=lambda item: item[0])
    return entries


# ---------------------------------------------------------------------------
# v2 signing
# https://source.android.com/docs/security/features/apksigning/v2
# ---------------------------------------------------------------------------


def _lp(data: bytes) -> bytes:
    """A u32-length-prefixed blob."""
    return struct.pack("<I", len(data)) + data


def _seq(items: list[bytes]) -> bytes:
    """A length-prefixed sequence of length-prefixed items."""
    return _lp(b"".join(_lp(item) for item in items))


def _sign_v2(apk_path: str, keystore_path: str, password: str) -> None:
    private_key, cert = load_key_and_cert(keystore_path, password)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(
            "the built-in v2 signer only supports RSA keys; "
            f"{keystore_path} holds a {type(private_key).__name__}"
        )

    apk_data = Path(apk_path).read_bytes()
    eocd = find_eocd(apk_data)

    contents = apk_data[: eocd.cd_offset]
    central_directory = apk_data[eocd.cd_offset : eocd.cd_offset + eocd.cd_size]
    # The EOCD is digested with its central-directory-offset field pointing at
    # the signing block. The block is inserted exactly where the central
    # directory starts today, so the field already holds the right value.
    end_of_central_directory = apk_data[eocd.offset :]

    content_digest = _content_digest(contents, central_directory, end_of_central_directory)

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed_data = (
        _seq([struct.pack("<I", _V2_ALG_RSASSA_PKCS1_SHA256) + _lp(content_digest)])
        + _seq([cert_der])
        + _lp(b"")  # no additional attributes
    )

    signature = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    public_key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer = (
        _lp(signed_data)
        + _seq([struct.pack("<I", _V2_ALG_RSASSA_PKCS1_SHA256) + _lp(signature)])
        + _lp(public_key_der)
    )

    signers = _seq([signer])
    pair = struct.pack("<QI", len(signers) + 4, APK_V2_BLOCK_ID) + signers
    # Both size fields count every byte after the first one — the pairs, the
    # trailing size field itself and the magic.
    block_size = len(pair) + 8 + 16
    signing_block = (
        struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    )

    new_eocd = bytearray(end_of_central_directory)
    struct.pack_into("<I", new_eocd, 16, eocd.cd_offset + len(signing_block))

    Path(apk_path).write_bytes(contents + signing_block + central_directory + bytes(new_eocd))


def _content_digest(*sections: bytes) -> bytes:
    """The v2 CHUNKED_SHA256 digest.

    Every section is split into 1 MB chunks and all the chunk digests go into a
    *single* flat list — not one top-level digest per section.
    """
    chunk_digests = []
    for section in sections:
        for offset in range(0, len(section), _V2_CHUNK_SIZE):
            chunk = section[offset : offset + _V2_CHUNK_SIZE]
            prefix = _V2_CHUNK_PREFIX + struct.pack("<I", len(chunk))
            chunk_digests.append(hashlib.sha256(prefix + chunk).digest())

    top = _V2_TOP_LEVEL_PREFIX + struct.pack("<I", len(chunk_digests)) + b"".join(chunk_digests)
    return hashlib.sha256(top).digest()
