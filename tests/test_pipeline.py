import os
import zipfile

import pytest

from fuin.server.pipeline import PipelineOptions, run_pipeline
from tests.conftest import make_minimal_apk


@pytest.fixture
def input_apk(tmp_path):
    path = tmp_path / "input.apk"
    path.write_bytes(make_minimal_apk("com.example.MyApp"))
    return str(path)


def test_pipeline_produces_apk(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, sig, report = run_pipeline(input_apk)

    assert os.path.exists(packed_path)
    assert packed_path.endswith(".apk")


def test_pipeline_output_is_valid_zip(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, _, _ = run_pipeline(input_apk)

    assert zipfile.is_zipfile(packed_path)


def test_pipeline_output_has_stub_dex(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, _, _ = run_pipeline(input_apk)

    with zipfile.ZipFile(packed_path) as z:
        names = z.namelist()
        assert "classes.dex" in names
        assert "assets/encrypted.dex" in names
        assert "assets/key.bin" in names


def test_pipeline_respects_native_and_asset_options(tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    apk = tmp_path / "input.apk"
    apk.write_bytes(
        make_minimal_apk(
            extra_files={
                "lib/arm64-v8a/libgame.so": b"\x7fELF" + b"\x00" * 16,
                "assets/config.json": b'{"debug": false}',
            }
        )
    )

    packed_path, _, _ = run_pipeline(
        str(apk),
        options=PipelineOptions(encrypt_native=False, encrypt_assets=False),
    )

    with zipfile.ZipFile(packed_path) as z:
        names = z.namelist()
        assert "lib/arm64-v8a/libgame.so" in names
        assert "assets/config.json" in names
        assert not any(name.startswith("assets/encrypted_libs/") for name in names)
        assert not any(name.startswith("assets/encrypted_res/") for name in names)


def test_pipeline_respects_exclude_files(tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    apk = tmp_path / "input.apk"
    apk.write_bytes(
        make_minimal_apk(
            extra_files={
                "assets/public.txt": b"public",
                "assets/private.txt": b"private",
            }
        )
    )

    packed_path, _, _ = run_pipeline(
        str(apk),
        options=PipelineOptions(exclude_files=("assets/public.txt",)),
    )

    with zipfile.ZipFile(packed_path) as z:
        names = z.namelist()
        assert "assets/public.txt" in names
        assert "assets/private.txt" not in names
        assert any(name.startswith("assets/encrypted_res/") for name in names)


def test_pipeline_writes_security_policy_from_options(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))

    packed_path, _, _ = run_pipeline(
        input_apk,
        options=PipelineOptions(root_detection=True, emulator_detection=True),
    )

    with zipfile.ZipFile(packed_path) as z:
        policy = z.read("assets/security_policy.json")
        assert b'"root_detection": true' in policy
        assert b'"emulator_detection": true' in policy


def test_pipeline_original_dex_not_in_output(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))

    with zipfile.ZipFile(input_apk) as z:
        original_dex = z.read("classes.dex")

    packed_path, _, _ = run_pipeline(input_apk)

    with zipfile.ZipFile(packed_path) as z:
        assert z.read("classes.dex") != original_dex


def test_pipeline_returns_sha256(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    _, sig, _ = run_pipeline(input_apk)

    assert len(sig) == 64  # SHA-256 hex
    assert all(c in "0123456789abcdef" for c in sig)


def test_pipeline_progress_callback(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    steps = []

    def on_progress(step, pct):
        steps.append((step, pct))

    run_pipeline(input_apk, progress=on_progress)

    assert len(steps) > 0
    assert steps[-1] == ("done", 100)


def test_pipeline_missing_dex_raises(tmp_path, monkeypatch):
    import io

    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
    apk_path = str(tmp_path / "no_dex.apk")
    (tmp_path / "no_dex.apk").write_bytes(buf.getvalue())

    with pytest.raises(ValueError, match="classes.dex"):
        run_pipeline(apk_path)
