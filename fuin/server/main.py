"""
fuin Packer Server (FastAPI).

Endpoints:
  GET    /                              — Web UI
  POST   /pack                          — Upload APK → start async job → return job_id
  GET    /jobs/{job_id}/stream          — SSE progress stream
  GET    /jobs/{job_id}                 — Poll job status
  GET    /apps/{app_id}/download        — Download the packed APK
  GET    /apps/{app_id}/mapping         — Download ProGuard mapping (if uploaded)
  GET    /apps                          — List all packed apps
  DELETE /apps/{app_id}                 — Delete a packed app
  POST   /apps/{app_id}/mapping/upload  — Upload ProGuard mapping.txt for an app
"""

import asyncio
import json
import logging
import os
import re
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from fuin import config
from fuin.analyze import analyze_targets
from fuin.server.database import App, JobRecord, init_db, make_engine, make_get_session
from fuin.server.jobs import JobStatus, create_job, get_job
from fuin.server.models import AppInfo, PackResult
from fuin.server.pipeline import analyze_apk, run_pipeline

log = logging.getLogger(__name__)

_engine = make_engine(config.DATABASE_URL)
get_session = make_get_session(_engine)

_STATIC_DIR = Path(__file__).parent / "static"


def _safe_package_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._\-]", "_", name) or "unknown"


def verify_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = None,  # query param fallback for SSE (EventSource can't set headers)
):
    provided = x_api_key or api_key
    if not config.ADMIN_API_KEY or provided != config.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _cleanup_old_records() -> int:
    """Delete apps and their files older than CLEANUP_OLDER_THAN_DAYS. Returns count deleted."""
    if not config.CLEANUP_OLDER_THAN_DAYS:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=config.CLEANUP_OLDER_THAN_DAYS)
    deleted = 0
    with Session(_engine) as s:
        old = s.query(App).filter(App.created_at < cutoff).all()
        for app in old:
            if app.packed_apk_path and os.path.exists(app.packed_apk_path):
                try:
                    os.unlink(app.packed_apk_path)
                except OSError:
                    pass
            if app.mapping_path and os.path.exists(app.mapping_path):
                try:
                    os.unlink(app.mapping_path)
                except OSError:
                    pass
            s.delete(app)
            deleted += 1
        # Also clean old job records
        old_jobs = s.query(JobRecord).filter(JobRecord.created_at < cutoff).all()
        for jr in old_jobs:
            s.delete(jr)
        s.commit()
    if deleted:
        log.info("cleanup: deleted %d old packed apps", deleted)
    return deleted


async def _fire_webhook(url: str, payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=payload)
    except Exception as e:
        log.warning("webhook POST to %s failed: %s", url, e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not config.ADMIN_API_KEY:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
    init_db(_engine)
    _cleanup_old_records()
    yield


app = FastAPI(title="fuin Packer Server", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    html_path = _STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(html_path.read_text())


@app.post("/analyze", dependencies=[Depends(verify_api_key)])
async def analyze_apk_targets(
    file: UploadFile = File(...),
):
    """Upload APK → return list of encryptable files (for UI preview)."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")

    apk_bytes = await file.read()

    if len(apk_bytes) < 4 or apk_bytes[:4] != b"PK\x03\x04":
        raise HTTPException(
            status_code=400, detail="File does not appear to be a valid APK (invalid ZIP header)"
        )

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, analyze_targets, tmp_path)
        return result
    finally:
        os.unlink(tmp_path)


@app.post("/pack", dependencies=[Depends(verify_api_key)])
async def pack_apk(
    file: UploadFile = File(...),
    app_class: str = Form(default=""),
    webhook_url: str = Form(default=""),
    exclude_files: str = Form(default=""),
    encrypt_native: bool = Form(default=True),
    encrypt_assets: bool = Form(default=True),
    encrypt_strings: bool = Form(default=False),
    root_detection: bool = Form(default=False),
    emulator_detection: bool = Form(default=False),
):
    """Upload APK → start background job → return job_id immediately."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")

    apk_bytes = await file.read()

    if len(apk_bytes) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"APK too large: {len(apk_bytes) // (1024 * 1024)} MB "
                f"(limit: {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"
            ),
        )

    if len(apk_bytes) < 4 or apk_bytes[:4] != b"PK\x03\x04":
        raise HTTPException(
            status_code=400, detail="File does not appear to be a valid APK (invalid ZIP header)"
        )

    job = create_job()

    # Persist job record to DB immediately
    with Session(_engine) as s:
        s.add(JobRecord(job_id=job.job_id, status="pending"))
        s.commit()

    async def _run() -> None:
        tmp_path: str | None = None
        try:
            job.status = JobStatus.running
            _db_update_job(job.job_id, status="running")

            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(apk_bytes)
                tmp_path = tmp.name

            loop = asyncio.get_event_loop()
            analysis = await loop.run_in_executor(None, analyze_apk, tmp_path)

            if not analysis.get("has_classes_dex"):
                raise ValueError("APK does not contain classes.dex")

            def _progress(step: str, pct: int) -> None:
                job.progress_step = step
                job.progress_pct = pct
                job.push({"status": "running", "step": step, "pct": pct})
                _db_update_job(job.job_id, status="running", step=step, pct=pct)

            packed_path, apk_sig, pack_report = await loop.run_in_executor(
                None,
                lambda: run_pipeline(tmp_path, app_class=app_class or None, progress=_progress),
            )

            def _save():
                entry = App(
                    package_name=analysis.get("package_name", "unknown"),
                    apk_signature=apk_sig,
                    packed_apk_path=packed_path,
                    analysis=analysis,
                    webhook_urls=webhook_url or config.WEBHOOK_URL or None,
                )
                with Session(_engine) as s:
                    s.add(entry)
                    s.commit()
                    s.refresh(entry)
                    return entry

            entry = await loop.run_in_executor(None, _save)
            result = PackResult(
                app_id=entry.app_id,
                package_name=entry.package_name,
                apk_signature=apk_sig,
                analysis=analysis,
                report=pack_report,
            ).model_dump()

            job.result = result
            job.status = JobStatus.done
            job.push({"status": JobStatus.done, "step": "done", "pct": 100, "result": result})
            _db_update_job(job.job_id, status="done", step="done", pct=100, app_id=entry.app_id)
            log.info("packed app_id=%s package=%s", entry.app_id, entry.package_name)

            # Fire webhooks
            urls = [
                u.strip() for u in (webhook_url + "," + config.WEBHOOK_URL).split(",") if u.strip()
            ]
            for url in urls:
                asyncio.create_task(_fire_webhook(url, {"event": "pack.done", "result": result}))

        except Exception as exc:
            log.exception("pack job %s failed", job.job_id)
            job.status = JobStatus.error
            job.error = str(exc)
            job.push({"status": JobStatus.error, "step": "error", "pct": 0, "error": str(exc)})
            _db_update_job(job.job_id, status="error", error=str(exc))
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


def _db_update_job(
    job_id: str,
    *,
    status: str | None = None,
    step: str | None = None,
    pct: int | None = None,
    app_id: str | None = None,
    error: str | None = None,
) -> None:
    try:
        with Session(_engine) as s:
            jr = s.get(JobRecord, job_id)
            if not jr:
                return
            if status:
                jr.status = status
            if step:
                jr.progress_step = step
            if pct is not None:
                jr.progress_pct = pct
            if app_id:
                jr.app_id = app_id
            if error:
                jr.error = error
            if status in ("done", "error"):
                jr.finished_at = datetime.now(UTC)
            s.commit()
    except Exception:
        pass  # DB errors must not kill the pack job


@app.get("/jobs/{job_id}/stream", dependencies=[Depends(verify_api_key)])
async def stream_job(job_id: str):
    """SSE stream: emits progress events until done or error."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def _sse():
        async for event in job.stream():
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(_sse(), media_type="text/event-stream")


@app.get("/jobs/{job_id}", dependencies=[Depends(verify_api_key)])
def get_job_status(job_id: str, db: Session = Depends(get_session)):
    """Poll-based job status — falls back to DB record for completed jobs after restart."""
    job = get_job(job_id)
    if job:
        return {
            "job_id": job.job_id,
            "status": job.status,
            "step": job.progress_step,
            "pct": job.progress_pct,
            "result": job.result,
            "error": job.error,
        }
    # Not in memory — check DB (survived server restart)
    jr = db.get(JobRecord, job_id)
    if not jr:
        raise HTTPException(status_code=404, detail="Job not found")
    result = None
    if jr.app_id:
        app_entry = db.get(App, jr.app_id)
        if app_entry:
            result = {
                "app_id": app_entry.app_id,
                "package_name": app_entry.package_name,
                "apk_signature": app_entry.apk_signature,
                "analysis": app_entry.analysis or {},
            }
    return {
        "job_id": jr.job_id,
        "status": jr.status,
        "step": jr.progress_step,
        "pct": jr.progress_pct,
        "result": result,
        "error": jr.error,
    }


@app.get("/apps/{app_id}/download", dependencies=[Depends(verify_api_key)])
def download_packed_apk(app_id: str, db: Session = Depends(get_session)):
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if not entry.packed_apk_path or not os.path.exists(entry.packed_apk_path):
        raise HTTPException(status_code=404, detail="Packed APK not found on disk")

    filename = f"{_safe_package_name(entry.package_name)}_packed.apk"
    return FileResponse(
        entry.packed_apk_path,
        media_type="application/vnd.android.package-archive",
        filename=filename,
    )


@app.post("/apps/{app_id}/mapping/upload", dependencies=[Depends(verify_api_key)])
async def upload_mapping(
    app_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_session),
):
    """Upload a ProGuard mapping.txt for an app (for deobfuscating crash stacks)."""
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Mapping file too large (max 50 MB)")

    mapping_dir = Path(config.PACKED_APK_DIR) / "mappings"
    mapping_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = mapping_dir / f"{app_id}_mapping.txt"
    mapping_path.write_bytes(content)

    entry.mapping_path = str(mapping_path)
    db.commit()
    return {"status": "uploaded", "app_id": app_id, "size_bytes": len(content)}


@app.get("/apps/{app_id}/mapping", dependencies=[Depends(verify_api_key)])
def download_mapping(app_id: str, db: Session = Depends(get_session)):
    """Download the ProGuard mapping.txt for an app."""
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if not entry.mapping_path or not os.path.exists(entry.mapping_path):
        raise HTTPException(status_code=404, detail="No mapping file for this app")
    return FileResponse(
        entry.mapping_path,
        media_type="text/plain",
        filename=f"{_safe_package_name(entry.package_name)}_mapping.txt",
    )


@app.get("/apps", response_model=list[AppInfo], dependencies=[Depends(verify_api_key)])
def list_apps(db: Session = Depends(get_session)):
    return [
        AppInfo(
            app_id=a.app_id,
            package_name=a.package_name,
            apk_signature=a.apk_signature,
            analysis=a.analysis,
            has_mapping=bool(a.mapping_path and os.path.exists(a.mapping_path)),
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in db.query(App).order_by(App.created_at.desc()).all()
    ]


@app.delete("/apps/{app_id}", dependencies=[Depends(verify_api_key)])
def delete_app(app_id: str, db: Session = Depends(get_session)):
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if entry.packed_apk_path and os.path.exists(entry.packed_apk_path):
        os.unlink(entry.packed_apk_path)
    if entry.mapping_path and os.path.exists(entry.mapping_path):
        try:
            os.unlink(entry.mapping_path)
        except OSError:
            pass
    db.delete(entry)
    db.commit()
    log.info("deleted app_id=%s", app_id)
    return {"status": "deleted"}


def run() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run("fuin.server.main:app", host="0.0.0.0", port=8000, reload=False)
