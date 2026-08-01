"""Signing tests.

signing.py had no direct coverage at all despite being the largest module in
the packer, and its pure-Python v1/v2 fallback — the path that runs whenever
the Android SDK is absent — was never exercised.

These call the fallback directly rather than going through ``sign_apk``, so
they behave the same whether or not apksigner happens to be installed.
"""

import struct
import zipfile
from pathlib import Path

import pytest

from fuin._constants import APK_SIG_BLOCK_MAGIC, APK_V2_BLOCK_ID
from fuin.keystore import create_debug_keystore, extract_cert_fingerprint
from fuin.signing import _find_eocd, _sign_v1, _sign_v2, verify_apk_signature
from tests.fixtures import make_minimal_apk


@pytest.fixture(scope="module")
def keystore(tmp_path_factory):
    """Module-scoped: RSA-2048 keygen is slow and the key content is irrelevant."""
    path = str(tmp_path_factory.mktemp("ks") / "debug.keystore")
    return create_debug_keystore(path)


@pytest.fixture
def apk(tmp_path):
    path = tmp_path / "in.apk"
    path.write_bytes(make_minimal_apk())
    return str(path)


def test_sign_v1_adds_manifest_and_signature_files(apk, keystore):
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)

    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
    alias = keystore.alias.upper()
    assert "META-INF/MANIFEST.MF" in names
    assert f"META-INF/{alias}.SF" in names
    assert f"META-INF/{alias}.RSA" in names


def test_sign_v1_digests_every_payload_entry(apk, keystore):
    with zipfile.ZipFile(apk) as z:
        payload = [n for n in z.namelist() if not n.startswith("META-INF/")]

    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)

    with zipfile.ZipFile(apk) as z:
        manifest = z.read("META-INF/MANIFEST.MF").decode()
    for name in payload:
        assert f"Name: {name}" in manifest
        assert manifest.count(f"Name: {name}") == 1
    assert "SHA-256-Digest:" in manifest


def test_sign_v1_preserves_payload_entries(apk, keystore):
    with zipfile.ZipFile(apk) as z:
        before = {n: z.read(n) for n in z.namelist()}

    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)

    with zipfile.ZipFile(apk) as z:
        after = {n: z.read(n) for n in z.namelist() if not n.startswith("META-INF/")}
    assert after == before


def test_sign_v1_is_idempotent_not_cumulative(apk, keystore):
    """Re-signing must replace the old signature, not stack a second one."""
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)

    with zipfile.ZipFile(apk) as z:
        meta = [n for n in z.namelist() if n.startswith("META-INF/")]
    assert len(meta) == 3


def test_sign_v2_inserts_signing_block(apk, keystore):
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    _sign_v2(apk, keystore.path, keystore.store_pass)

    data = Path(apk).read_bytes()
    assert APK_SIG_BLOCK_MAGIC in data
    assert struct.pack("<I", APK_V2_BLOCK_ID) in data


def test_sign_v2_output_is_still_a_readable_zip(apk, keystore):
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    with zipfile.ZipFile(apk) as z:
        before = {n: z.read(n) for n in z.namelist()}

    _sign_v2(apk, keystore.path, keystore.store_pass)

    assert zipfile.is_zipfile(apk)
    with zipfile.ZipFile(apk) as z:
        assert {n: z.read(n) for n in z.namelist()} == before


def test_sign_v2_updates_central_directory_offset(apk, keystore):
    """The EOCD must point past the inserted block, or the zip is unreadable."""
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    before = Path(apk).read_bytes()
    eocd = _find_eocd(before)
    cd_before = struct.unpack_from("<I", before, eocd + 16)[0]

    _sign_v2(apk, keystore.path, keystore.store_pass)

    after = Path(apk).read_bytes()
    cd_after = struct.unpack_from("<I", after, _find_eocd(after) + 16)[0]
    assert cd_after > cd_before
    assert cd_after == cd_before + (len(after) - len(before))


def test_find_eocd_returns_none_without_a_zip():
    assert _find_eocd(b"not a zip at all" * 10) is None


def test_verify_returns_false_when_apksigner_missing(apk, monkeypatch):
    monkeypatch.setattr("fuin.signing.find_build_tool", lambda name: None)
    assert verify_apk_signature(apk) is False


def test_cert_fingerprint_is_stable_sha256(keystore):
    fp = extract_cert_fingerprint(keystore.path, keystore.store_pass)
    assert len(fp) == 32
    assert fp == extract_cert_fingerprint(keystore.path, keystore.store_pass)


def test_cert_fingerprint_rejects_wrong_password(keystore):
    with pytest.raises(ValueError, match=r"(?i)mac|decrypt|invalid"):
        extract_cert_fingerprint(keystore.path, "wrong-password")
