import zipfile

from fuin.apk import get_apk_info, patch_manifest
from fuin.contract import STUB_CLASS
from tests.fixtures import make_axml, make_minimal_apk
from tests.fixtures.apk import make_apk_with_manifest


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


def test_sdk_versions_are_read_through_the_resource_map(tmp_path):
    """`android:*` attributes are only reachable via the resource map.

    fuin looked for that chunk under the wrong type word, so it parsed zero
    resource IDs and reported min/target SDK as None for every real APK. The
    old fixture emitted the same wrong type and so agreed with the bug.
    """
    apk = tmp_path / "input.apk"
    apk.write_bytes(make_apk_with_manifest(make_axml(min_sdk=24, target_sdk=35)))

    info = get_apk_info(str(apk))

    assert info["min_sdk"] == 24
    assert info["target_sdk"] == 35
    assert info["package_name"] == "com.example.test"


def test_sdk_versions_survive_the_patch(tmp_path):
    """Rewriting the string pool must not disturb the resource map."""
    apk = tmp_path / "input.apk"
    out = tmp_path / "output.apk"
    apk.write_bytes(make_apk_with_manifest(make_axml(min_sdk=24, target_sdk=35)))

    patch_manifest(str(apk), str(out), None)

    info = get_apk_info(str(out))
    assert (info["min_sdk"], info["target_sdk"]) == (24, 35)


def test_unreadable_apk_still_returns_the_full_shape(tmp_path):
    """The error path used to return a two-key dict every caller then KeyError'd on."""
    junk = tmp_path / "broken.apk"
    junk.write_bytes(b"not a zip")

    info = get_apk_info(str(junk))

    assert info["error"]
    assert info["package_name"] == "unknown"
    for key in ("dex_files", "dex_count", "entry_count", "file_size_bytes", "permissions"):
        assert key in info
