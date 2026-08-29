import os
import time

import pytest
from fastapi.testclient import TestClient

from fuin.server import deps, jobs
from fuin.server.main import app
from tests.fixtures import make_minimal_apk

API_KEY = "test-key"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FUIN_API_KEY", API_KEY)
    monkeypatch.setenv("FUIN_PACKED_DIR", str(tmp_path / "packed"))
    monkeypatch.setenv("FUIN_DATABASE_URL", f"sqlite:///{tmp_path}/test.db")

    # Settings are read from the environment per call, so only the cached
    # engine and the in-memory job store need clearing between tests.
    deps.reset_engine()
    jobs.reset_jobs()

    with TestClient(app) as c:
        yield c

    deps.reset_engine()
    jobs.reset_jobs()


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


def test_health_needs_no_auth(client):
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_wrong_api_key_is_rejected(client):
    resp = client.get("/apps", headers={"X-API-Key": "not-the-key"})

    assert resp.status_code == 401


@pytest.mark.parametrize("route", ["/pack", "/analyze"])
def test_upload_limit_is_enforced_on_every_upload_route(client, monkeypatch, route):
    """/analyze had no limit at all, and /pack only checked after buffering."""
    monkeypatch.setenv("FUIN_MAX_UPLOAD_MB", "1")
    # Incompressible, so the upload really is over the limit on the wire.
    oversized = make_minimal_apk(dex_content=os.urandom(2 * 1024 * 1024))

    resp = client.post(
        route,
        files={"file": ("big.apk", oversized, "application/vnd.android.package-archive")},
        headers={"X-API-Key": API_KEY},
    )

    assert resp.status_code == 413


def test_pack_job_runs_to_completion_and_persists_the_app(client):
    """The only test that actually executes the async job body."""
    resp = client.post(
        "/pack",
        files={"file": ("test.apk", make_minimal_apk(), "application/octet-stream")},
        headers={"X-API-Key": API_KEY},
    )
    job_id = resp.json()["job_id"]

    status = _await_terminal(client, job_id)
    assert status["status"] == "done", status

    listed = client.get("/apps", headers={"X-API-Key": API_KEY}).json()
    assert len(listed) == 1
    assert listed[0]["package_name"] == "com.example.test"

    download = client.get(f"/apps/{listed[0]['app_id']}/download", headers={"X-API-Key": API_KEY})
    assert download.status_code == 200
    assert download.content.startswith(b"PK\x03\x04")


def test_pack_job_records_an_error_for_an_apk_without_dex(client):
    resp = client.post(
        "/pack",
        files={"file": ("test.apk", _apk_without_dex(), "application/octet-stream")},
        headers={"X-API-Key": API_KEY},
    )

    status = _await_terminal(client, resp.json()["job_id"])

    assert status["status"] == "error"
    assert "classes.dex" in status["error"]


def test_job_error_does_not_leak_server_paths(client, monkeypatch):
    """`str(exc)` on an OSError carries temp and keystore paths to the client."""
    import fuin.server.services.pack_service as pack_service

    def boom(*args, **kwargs):
        raise OSError("/srv/secret/keystore.p12: Permission denied")

    monkeypatch.setattr(pack_service, "analyze_apk", boom)

    resp = client.post(
        "/pack",
        files={"file": ("test.apk", make_minimal_apk(), "application/octet-stream")},
        headers={"X-API-Key": API_KEY},
    )
    status = _await_terminal(client, resp.json()["job_id"])

    assert status["status"] == "error"
    assert "/srv/secret" not in status["error"]
    assert "OSError" in status["error"]


def test_jobs_stranded_by_a_restart_are_failed_at_startup(client):
    """The in-memory store does not survive a restart; the rows do."""
    from sqlalchemy.orm import Session

    from fuin.server.repositories import JobRepository
    from fuin.server.services.cleanup_service import fail_stranded_jobs

    engine = deps.get_engine()
    with Session(engine) as session:
        JobRepository(session).create("orphan-job", status="running")
        session.commit()

    assert fail_stranded_jobs(engine) == 1

    resp = client.get("/jobs/orphan-job", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"


def _apk_without_dex() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
    return buf.getvalue()


def _await_terminal(client, job_id: str, timeout: float = 60.0) -> dict:
    """Poll until the background job reaches a terminal state.

    TestClient drives the event loop only while a request is in flight, so
    polling is what lets the spawned task make progress at all. The sleep in
    between gives the pipeline's executor thread room to actually run.
    """
    deadline = time.monotonic() + timeout
    payload: dict = {}
    while time.monotonic() < deadline:
        payload = client.get(f"/jobs/{job_id}", headers={"X-API-Key": API_KEY}).json()
        if payload.get("status") in ("done", "error"):
            return payload
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never finished: {payload}")
