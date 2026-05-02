import os
import zipfile

import pytest

from fuin.server.pipeline import run_pipeline
from tests.conftest import make_minimal_apk


@pytest.fixture
def input_apk(tmp_path):
    path = tmp_path / "input.apk"
    path.write_bytes(make_minimal_apk("com.example.MyApp"))
    return str(path)


def test_pipeline_produces_apk(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, sig = run_pipeline(input_apk)

    assert os.path.exists(packed_path)
    assert packed_path.endswith(".apk")


def test_pipeline_output_is_valid_zip(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, _ = run_pipeline(input_apk)

    assert zipfile.is_zipfile(packed_path)


def test_pipeline_output_has_stub_dex(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    packed_path, _ = run_pipeline(input_apk)

    with zipfile.ZipFile(packed_path) as z:
        names = z.namelist()
        assert "classes.dex" in names
        assert "assets/encrypted.dex" in names
        assert "assets/key.bin" in names


def test_pipeline_original_dex_not_in_output(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))

    with zipfile.ZipFile(input_apk) as z:
        original_dex = z.read("classes.dex")

    packed_path, _ = run_pipeline(input_apk)

    with zipfile.ZipFile(packed_path) as z:
        assert z.read("classes.dex") != original_dex


def test_pipeline_returns_sha256(input_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    _, sig = run_pipeline(input_apk)

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
