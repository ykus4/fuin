"""Signing tests.

signing.py had no direct coverage at all despite being the largest module in
the packer, and its pure-Python v1/v2 fallback — the path that runs whenever
the Android SDK is absent — was never exercised.

These call the fallback directly rather than going through ``sign_apk``, so
they behave the same whether or not apksigner happens to be installed.
"""

import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from fuin.apk.constants import APK_SIG_BLOCK_MAGIC, APK_V2_BLOCK_ID
from fuin.apk.keystore import create_debug_keystore, extract_cert_fingerprint
from fuin.apk.signing import _sign_v1, _sign_v2, verify_apk_signature
from fuin.apk.tools import find_build_tool
from fuin.apk.zip_format import ZipFormatError, find_eocd
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
    cd_before = find_eocd(before).cd_offset

    _sign_v2(apk, keystore.path, keystore.store_pass)

    after = Path(apk).read_bytes()
    cd_after = find_eocd(after).cd_offset
    assert cd_after > cd_before
    assert cd_after == cd_before + (len(after) - len(before))


def test_sign_v2_block_size_fields_agree_with_the_block(apk, keystore):
    """Both u64 size fields count every byte after the first one.

    Getting this wrong does not corrupt the ZIP — it just makes the block
    undiscoverable, so the APK silently ships with no v2 signature at all.
    """
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    _sign_v2(apk, keystore.path, keystore.store_pass)

    data = Path(apk).read_bytes()
    magic_at = data.index(APK_SIG_BLOCK_MAGIC)
    size_after = struct.unpack_from("<Q", data, magic_at - 8)[0]
    block_start = magic_at + len(APK_SIG_BLOCK_MAGIC) - size_after - 8
    size_before = struct.unpack_from("<Q", data, block_start)[0]

    assert size_before == size_after
    assert size_before == (magic_at + len(APK_SIG_BLOCK_MAGIC)) - (block_start + 8)
    # The block must sit immediately before the central directory.
    assert magic_at + len(APK_SIG_BLOCK_MAGIC) == find_eocd(data).cd_offset


def test_sf_declares_the_v2_signature(apk, keystore):
    """Without this attribute, stripping the v2 block downgrades to v1-only."""
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)

    with zipfile.ZipFile(apk) as z:
        sf = z.read(f"META-INF/{keystore.alias.upper()}.SF").decode()
    assert "X-Android-APK-Signed: 2" in sf


def test_sign_v1_rejects_duplicate_entries(tmp_path, keystore):
    """Duplicate names are a masquerading trick; collapsing them hides it."""
    path = tmp_path / "dup.apk"
    path.write_bytes(make_minimal_apk())
    with zipfile.ZipFile(path, "a") as z, pytest.warns(UserWarning, match="Duplicate name"):
        z.writestr("classes.dex", b"second copy")

    with pytest.raises(ValueError, match="duplicate entry"):
        _sign_v1(str(path), keystore.path, keystore.alias, keystore.store_pass)


@pytest.mark.skipif(find_build_tool("apksigner") is None, reason="apksigner not installed")
def test_pure_python_signature_verifies_with_apksigner(apk, keystore):
    """The only assertion that proves the fallback signer is actually correct.

    Structural assertions passed for a v2 block Android silently ignored.
    """
    _sign_v1(apk, keystore.path, keystore.alias, keystore.store_pass)
    _sign_v2(apk, keystore.path, keystore.store_pass)

    result = subprocess.run(
        [
            find_build_tool("apksigner"),
            "verify",
            "--verbose",
            # The fixture APK has no parseable manifest, so minSdk must be told.
            "--min-sdk-version",
            "24",
            "--max-sdk-version",
            "34",
            apk,
        ],
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "v2 scheme (APK Signature Scheme v2): true" in output


def test_find_eocd_rejects_input_that_is_not_a_zip():
    with pytest.raises(ZipFormatError):
        find_eocd(b"not a zip at all" * 10)


def test_verify_returns_false_when_apksigner_missing(apk, monkeypatch):
    monkeypatch.setattr("fuin.apk.signing.find_build_tool", lambda name: None)
    assert verify_apk_signature(apk) is False


def test_cert_fingerprint_is_stable_sha256(keystore):
    fp = extract_cert_fingerprint(keystore.path, keystore.store_pass)
    assert len(fp) == 32
    assert fp == extract_cert_fingerprint(keystore.path, keystore.store_pass)


def test_cert_fingerprint_rejects_wrong_password(keystore):
    with pytest.raises(ValueError, match=r"(?i)mac|decrypt|invalid"):
        extract_cert_fingerprint(keystore.path, "wrong-password")
