import zipfile

from fuin.apk import inject_encrypted_dex, zipalign
from fuin.crypto import encrypt_dex, generate_key
from tests.conftest import make_minimal_apk

STUB_DEX = b"dex\n035\x00" + b"\x00" * 100


def test_inject_produces_valid_zip(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(str(apk), encrypted, key, "com.example.MyApp", str(out), stub_dex=STUB_DEX)

    assert zipfile.is_zipfile(str(out))


def test_inject_contains_stub_dex(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(str(apk), encrypted, key, "com.example.MyApp", str(out), stub_dex=STUB_DEX)

    with zipfile.ZipFile(str(out)) as z:
        assert z.read("classes.dex") == STUB_DEX


def test_inject_contains_encrypted_assets(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    key = generate_key()
    encrypted = encrypt_dex(b"fake dex", key)
    inject_encrypted_dex(str(apk), encrypted, key, "com.example.MyApp", str(out), stub_dex=STUB_DEX)

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
    inject_encrypted_dex(str(apk), encrypted, key, "com.example.MyApp", str(out), stub_dex=STUB_DEX)

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
        stub_dex=STUB_DEX,
        encrypted_extra_dex=encrypt_dex(b"extra bundle", key),
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
