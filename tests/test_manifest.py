import zipfile

from fuin.manifest import STUB_CLASS, patch_manifest
from tests.conftest import make_minimal_apk


def _read_manifest(apk_path: str) -> bytes:
    with zipfile.ZipFile(apk_path) as z:
        return z.read("AndroidManifest.xml")


def test_patch_replaces_app_class(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk("com.example.MyApp"))

    original = patch_manifest(str(apk), str(out), None)

    assert original == "com.example.MyApp"
    manifest = _read_manifest(str(out))
    assert STUB_CLASS.encode("utf-16-le") in manifest


def test_patch_removes_original_class(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk("com.example.MyApp"))

    patch_manifest(str(apk), str(out), None)

    manifest = _read_manifest(str(out))
    assert "com.example.MyApp".encode("utf-16-le") not in manifest


def test_patch_with_explicit_app_class(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk("com.example.MyApp"))

    original = patch_manifest(str(apk), str(out), "com.example.MyApp")

    assert original == "com.example.MyApp"


def test_patch_is_valid_zip(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    patch_manifest(str(apk), str(out), None)

    assert zipfile.is_zipfile(str(out))


def test_other_files_untouched(tmp_path):
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_minimal_apk())

    patch_manifest(str(apk), str(out), None)

    with zipfile.ZipFile(str(apk)) as zin, zipfile.ZipFile(str(out)) as zout:
        for name in zin.namelist():
            if name == "AndroidManifest.xml":
                continue
            assert zin.read(name) == zout.read(name)


def test_patch_idempotent_on_stub(tmp_path):
    """Patching an already-patched APK should not break anything."""
    apk = tmp_path / "input.apk"
    out1 = tmp_path / "out1.apk"
    out2 = tmp_path / "out2.apk"
    apk.write_bytes(make_minimal_apk("com.example.MyApp"))

    patch_manifest(str(apk), str(out1), None)
    patch_manifest(str(out1), str(out2), STUB_CLASS)

    assert zipfile.is_zipfile(str(out2))
