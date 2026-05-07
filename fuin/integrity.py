"""
Anti-tamper: certificate fingerprint extraction and embedding.

At pack time, extracts the SHA-256 fingerprint of the signing certificate
and embeds it as assets/cert_fingerprint.bin. The stub verifies the APK's
signing certificate matches this fingerprint at runtime.
"""

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.serialization import pkcs12

CERT_FINGERPRINT_ASSET = "assets/cert_fingerprint.bin"


def extract_cert_fingerprint(keystore_path: str, password: str) -> bytes:
    """Extract SHA-256 fingerprint of the signing certificate from a PKCS12 keystore.

    Returns 32 bytes (SHA-256 digest of DER-encoded certificate).
    """
    p12_data = Path(keystore_path).read_bytes()
    _, cert, _ = pkcs12.load_key_and_certificates(p12_data, password.encode())
    if cert is None:
        raise ValueError("No certificate found in keystore")

    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(cert_der).digest()
