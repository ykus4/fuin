"""PKCS12 keystore handling: resolution, loading, debug-keystore creation.

Everything that reads or writes a keystore lives here. Previously the same
``pkcs12.load_key_and_certificates`` preamble appeared in three modules, and
keystore *policy* (which keystore to use, and the debug fallback) sat in the
packing orchestrator.
"""

import datetime
import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from fuin.config import Settings
    from fuin.packer import PackOptions

log = logging.getLogger(__name__)

DEBUG_ALIAS = "fuin_debug"
DEBUG_PASSWORD = "android"


class Keystore(NamedTuple):
    """A resolved keystore and the credentials needed to use it."""

    path: str
    alias: str
    store_pass: str
    key_pass: str


def load_key_and_cert(keystore_path: str, password: str) -> tuple[Any, x509.Certificate]:
    """Load the private key and certificate from a PKCS12 keystore."""
    p12_data = Path(keystore_path).read_bytes()
    private_key, cert, _ = pkcs12.load_key_and_certificates(p12_data, password.encode())
    if cert is None:
        raise ValueError(f"No certificate found in keystore: {keystore_path}")
    return private_key, cert


def extract_cert_fingerprint(keystore_path: str, password: str) -> bytes:
    """SHA-256 digest of the DER-encoded signing certificate (32 bytes).

    Embedded as ``assets/cert_fingerprint.bin`` so the stub can verify at
    runtime that the APK still carries the signature it was packed for.
    """
    _, cert = load_key_and_cert(keystore_path, password)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()


def create_debug_keystore(keystore_path: str) -> Keystore:
    """Create a throwaway PKCS12 debug keystore (no keytool required)."""
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
        name=DEBUG_ALIAS.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(DEBUG_PASSWORD.encode()),
    )
    Path(keystore_path).write_bytes(p12)
    return Keystore(keystore_path, DEBUG_ALIAS, DEBUG_PASSWORD, DEBUG_PASSWORD)


def resolve(options: "PackOptions", settings: "Settings", tmpdir: str) -> Keystore:
    """Pick the keystore to sign with, falling back to a debug keystore.

    Explicit options win over configured settings; if either the path or a
    password is missing there is nothing usable, so a debug keystore is
    generated inside ``tmpdir``.
    """
    path = options.keystore_path or settings.keystore_path
    alias = options.keystore_alias or settings.keystore_alias
    store_pass = options.keystore_store_pass or settings.keystore_store_pass
    key_pass = options.keystore_key_pass or settings.keystore_key_pass

    if not path or not store_pass or not key_pass:
        log.warning("no keystore configured — using temporary debug keystore")
        return create_debug_keystore(str(Path(tmpdir) / "debug.keystore"))
    return Keystore(path, alias, store_pass, key_pass)
