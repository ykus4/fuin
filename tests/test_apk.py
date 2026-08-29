import io
import zipfile

import pytest

from fuin.apk import InjectedAssets, inject_encrypted_dex, zipalign
from fuin.apk.zip_format import ZipFormatError
from fuin.apk.zipalign import PAGE_ALIGNMENT, _zipalign_py, entry_alignment_report
from fuin.encryption.aes import encrypt_dex, generate_key
from tests.fixtures import make_minimal_apk

STUB_DEX = b"dex\n035\x00" + b"\x00" * 100


def test_inject_produces_valid_zip(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(
        str(apk), encrypted, key, "com.example.MyApp", str(out), InjectedAssets(stub_dex=STUB_DEX)
    )

    assert zipfile.is_zipfile(str(out))


def test_inject_contains_stub_dex(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(
        str(apk), encrypted, key, "com.example.MyApp", str(out), InjectedAssets(stub_dex=STUB_DEX)
    )

    with zipfile.ZipFile(str(out)) as z:
        assert z.read("classes.dex") == STUB_DEX


def test_inject_contains_encrypted_assets(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(
        str(apk), encrypted, key, "com.example.MyApp", str(out), InjectedAssets(stub_dex=STUB_DEX)
    )

    with zipfile.ZipFile(str(out)) as z:
        names = z.namelist()
        assert "assets/encrypted.dex" in names
        assert "assets/key.bin" in names
        assert "assets/original_app_class.txt" in names
        assert z.read("assets/key.bin") == key
        assert z.read("assets/original_app_class.txt") == b"com.example.MyApp"


def test_inject_removes_original_dex(tmp_path):
    """Original classes.dex should be replaced, not duplicated."""
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    original_dex = b"original bytecode" * 10
    apk.write_bytes(make_minimal_apk(dex_content=original_dex))

    key = generate_key()
    encrypted = encrypt_dex(original_dex, key)
    inject_encrypted_dex(
        str(apk), encrypted, key, "com.example.MyApp", str(out), InjectedAssets(stub_dex=STUB_DEX)
    )

    with zipfile.ZipFile(str(out)) as z:
        assert z.read("classes.dex") == STUB_DEX
        assert original_dex not in z.read("classes.dex")


def test_inject_with_extra_dex(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk(extra_dex={"classes2.dex": b"extra dex data"}))

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(
        str(apk),
        encrypted,
        key,
        "com.example.MyApp",
        str(out),
        InjectedAssets(
            stub_dex=STUB_DEX,
            encrypted_extra_dex=encrypt_dex(b"extra bundle", key),
        ),
    )

    with zipfile.ZipFile(str(out)) as z:
        assert "assets/encrypted_extra.dex" in z.namelist()


def test_zipalign_produces_valid_zip(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    zipalign(str(apk), str(out))

    assert zipfile.is_zipfile(str(out))


def test_zipalign_preserves_contents(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    zipalign(str(apk), str(out))

    with zipfile.ZipFile(str(apk)) as zin, zipfile.ZipFile(str(out)) as zout:
        for name in zin.namelist():
            assert zin.read(name) == zout.read(name)


# ---------------------------------------------------------------------------
# The pure-Python aligner.
#
# These call `_zipalign_py` directly. Going through `zipalign` would silently
# test the SDK binary on any machine that has one — which is why the fallback
# shipped broken: it crashed on its first `struct.unpack` for every input, and
# no test ever reached it.
# ---------------------------------------------------------------------------


def make_mixed_apk(*, so_size: int = 606, extra: bytes = b"") -> bytes:
    """An APK with stored and deflated entries, and a pre-existing extra field.

    Stored entries are what alignment is about, and a stored entry that already
    carries an extra field is what the padding arithmetic gets wrong.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"M" * 37, zipfile.ZIP_DEFLATED)
        so = zipfile.ZipInfo("lib/arm64-v8a/libfoo.so")
        so.compress_type = zipfile.ZIP_STORED
        so.extra = extra
        z.writestr(so, b"NATIVE" * so_size)
        z.writestr("classes.dex", b"D" * 999, zipfile.ZIP_DEFLATED)
        arsc = zipfile.ZipInfo("resources.arsc")
        arsc.compress_type = zipfile.ZIP_STORED
        z.writestr(arsc, b"ARSC" * 53)
        asset = zipfile.ZipInfo("assets/a.bin")
        asset.compress_type = zipfile.ZIP_STORED
        z.writestr(asset, b"Z" * 7)
    return buf.getvalue()


@pytest.fixture
def mixed_apk(tmp_path):
    path = tmp_path / "mixed.apk"
    path.write_bytes(make_mixed_apk(extra=b"\x99\x99\x02\x00ab"))
    return path


def test_py_zipalign_aligns_every_stored_entry(mixed_apk, tmp_path):
    out = tmp_path / "aligned.apk"

    _zipalign_py(str(mixed_apk), str(out))

    offsets = entry_alignment_report(str(out))
    assert offsets, "no stored entries were found to check"
    for name, data_start in offsets.items():
        assert data_start % 4 == 0, f"{name} starts at {data_start}"


def test_py_zipalign_output_is_readable_and_identical(mixed_apk, tmp_path):
    """The central directory must be rewritten, not copied.

    Padding shifts every later local header; leaving the recorded offsets stale
    yields a file that is still 'a zip' but whose members cannot be read.
    """
    out = tmp_path / "aligned.apk"

    _zipalign_py(str(mixed_apk), str(out))

    with zipfile.ZipFile(mixed_apk) as before, zipfile.ZipFile(out) as after:
        assert after.testzip() is None
        assert before.namelist() == after.namelist()
        for info in before.infolist():
            assert after.read(info.filename) == before.read(info.filename)
            assert after.getinfo(info.filename).compress_type == info.compress_type


def test_py_zipalign_page_aligns_native_libraries(mixed_apk, tmp_path):
    """16 KiB pages are required by Android 15 for uncompressed .so entries."""
    out = tmp_path / "aligned.apk"

    _zipalign_py(str(mixed_apk), str(out), so_alignment=PAGE_ALIGNMENT)

    offsets = entry_alignment_report(str(out))
    assert offsets["lib/arm64-v8a/libfoo.so"] % PAGE_ALIGNMENT == 0
    # Everything else keeps the cheaper alignment.
    assert offsets["resources.arsc"] % 4 == 0
    assert offsets["resources.arsc"] % PAGE_ALIGNMENT != 0


def test_py_zipalign_is_idempotent(mixed_apk, tmp_path):
    once, twice = tmp_path / "1.apk", tmp_path / "2.apk"

    _zipalign_py(str(mixed_apk), str(once))
    _zipalign_py(str(once), str(twice))

    assert once.read_bytes() == twice.read_bytes()


def test_py_zipalign_refuses_an_already_signed_apk(tmp_path):
    """Aligning after signing shifts entry data and voids the v2 signature."""
    from fuin.apk.keystore import create_debug_keystore
    from fuin.apk.signing import _sign_v1, _sign_v2

    apk = tmp_path / "signed.apk"
    apk.write_bytes(make_minimal_apk())
    ks = create_debug_keystore(str(tmp_path / "debug.p12"))
    _sign_v1(str(apk), ks.path, ks.alias, ks.store_pass)
    _sign_v2(str(apk), ks.path, ks.store_pass)

    with pytest.raises(ZipFormatError, match="signing block"):
        _zipalign_py(str(apk), str(tmp_path / "out.apk"))


def test_py_zipalign_rejects_a_non_zip(tmp_path):
    junk = tmp_path / "junk.apk"
    junk.write_bytes(b"definitely not a zip" * 20)

    with pytest.raises(ZipFormatError):
        _zipalign_py(str(junk), str(tmp_path / "out.apk"))
