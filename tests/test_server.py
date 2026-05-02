import os

import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_minimal_apk

API_KEY = "test-key"


@pytest.fixture
def client(tmp_path):
    os.environ["FUIN_API_KEY"] = API_KEY
    os.environ["FUIN_PACKED_DIR"] = str(tmp_path / "packed")
    os.environ["FUIN_DATABASE_URL"] = f"sqlite:///{tmp_path}/test.db"

    # Re-import config to pick up new env vars
    import importlib

    import fuin.config as cfg

    importlib.reload(cfg)

    import fuin.server.main as srv_main

    importlib.reload(srv_main)

    with TestClient(srv_main.app) as c:
        yield c

    for key in ("FUIN_API_KEY", "FUIN_PACKED_DIR", "FUIN_DATABASE_URL"):
        os.environ.pop(key, None)


def test_ui_accessible(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_pack_requires_auth(client):
    resp = client.post(
        "/pack", files={"file": ("test.apk", b"PK\x03\x04", "application/octet-stream")}
    )
    assert resp.status_code == 401


def test_pack_rejects_non_apk(client):
    resp = client.post(
        "/pack",
        files={"file": ("test.txt", b"not an apk", "text/plain")},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 400


def test_pack_rejects_invalid_zip(client):
    resp = client.post(
        "/pack",
        files={"file": ("test.apk", b"not a zip", "application/octet-stream")},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 400


def test_pack_returns_job_id(client):
    apk_bytes = make_minimal_apk()
    resp = client.post(
        "/pack",
        files={"file": ("test.apk", apk_bytes, "application/vnd.android.package-archive")},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 200
    assert "job_id" in resp.json()


def test_list_apps_requires_auth(client):
    resp = client.get("/apps")
    assert resp.status_code == 401


def test_list_apps_empty(client):
    resp = client.get("/apps", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert resp.json() == []


def test_job_status_not_found(client):
    resp = client.get("/jobs/nonexistent-job-id", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404


def test_download_not_found(client):
    resp = client.get("/apps/nonexistent-app-id/download", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404


def test_delete_not_found(client):
    resp = client.delete("/apps/nonexistent-app-id", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404
