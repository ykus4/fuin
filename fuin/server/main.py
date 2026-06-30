"""fuin Packer Server (FastAPI).

Routes:
  GET    /                              — Web UI
  POST   /analyze                       — Preview encryption targets
  POST   /pack                          — Start async pack job → job_id
  GET    /jobs/{job_id}/stream          — SSE progress stream
  GET    /jobs/{job_id}                 — Poll job status
  GET    /apps                          — List packed apps
  GET    /apps/{app_id}/download        — Download packed APK
  GET    /apps/{app_id}/mapping         — Download ProGuard mapping
  POST   /apps/{app_id}/mapping/upload  — Upload ProGuard mapping
  DELETE /apps/{app_id}                 — Delete a packed app
"""

import asyncio
import json
import logging
import os
import re
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from fuin import config
from fuin._constants import ZIP_LOCAL_HEADER_MAGIC
from fuin.analyze import analyze_targets
from fuin.server.database import App, JobRecord
from fuin.server.deps import get_db, get_engine, verify_api_key
from fuin.server.jobs import create_job, get_job
from fuin.server.models import AppInfo
from fuin.server.services.cleanup_service import cleanup_old_records
from fuin.server.services.pack_service import run_pack_job

log = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


def _safe_package_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._\-]", "_", name) or "unknown"


def _ensure_valid_apk(apk_bytes: bytes, *, filename: str | None) -> None:
    if not filename or not filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")
    if len(apk_bytes) < 4 or not apk_bytes.startswith(ZIP_LOCAL_HEADER_MAGIC):
        raise HTTPException(
            status_code=400, detail="File does not appear to be a valid APK (invalid ZIP header)"
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.validate_server_config()
    engine = get_engine()
    cleanup_old_records(engine)
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
async def analyze_apk_targets(file: UploadFile = File(...)):
    apk_bytes = await file.read()
    _ensure_valid_apk(apk_bytes, filename=file.filename)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name

    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, analyze_targets, tmp_path)
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
    apk_bytes = await file.read()
    _ensure_valid_apk(apk_bytes, filename=file.filename)

    if len(apk_bytes) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"APK too large: {len(apk_bytes) // (1024 * 1024)} MB "
                f"(limit: {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"
            ),
        )

    engine = get_engine()
    job = create_job()
    with Session(engine) as s:
        s.add(JobRecord(job_id=job.job_id, status="pending"))
        s.commit()

    asyncio.create_task(
        run_pack_job(
            engine,
            job,
            apk_bytes,
            app_class=app_class,
            webhook_url=webhook_url,
            encrypt_native=encrypt_native,
            encrypt_assets=encrypt_assets,
            encrypt_strings=encrypt_strings,
            root_detection=root_detection,
            emulator_detection=emulator_detection,
            exclude_files=tuple(f.strip() for f in exclude_files.split(",") if f.strip()),
        )
    )
    return {"job_id": job.job_id}


@app.get("/jobs/{job_id}/stream", dependencies=[Depends(verify_api_key)])
async def stream_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def _sse():
        async for event in job.stream():
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(_sse(), media_type="text/event-stream")


@app.get("/jobs/{job_id}", dependencies=[Depends(verify_api_key)])
def get_job_status(job_id: str, db: Session = Depends(get_db)):
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
def download_packed_apk(app_id: str, db: Session = Depends(get_db)):
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if not entry.packed_apk_path or not os.path.exists(entry.packed_apk_path):
        raise HTTPException(status_code=404, detail="Packed APK not found on disk")
    return FileResponse(
        entry.packed_apk_path,
        media_type="application/vnd.android.package-archive",
        filename=f"{_safe_package_name(entry.package_name)}_packed.apk",
    )


@app.post("/apps/{app_id}/mapping/upload", dependencies=[Depends(verify_api_key)])
async def upload_mapping(
    app_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
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
def download_mapping(app_id: str, db: Session = Depends(get_db)):
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
def list_apps(db: Session = Depends(get_db)):
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
def delete_app(app_id: str, db: Session = Depends(get_db)):
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if entry.packed_apk_path and os.path.exists(entry.packed_apk_path):
        try:
            os.unlink(entry.packed_apk_path)
        except OSError:
            pass
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
