"""
fuin Packer Server (FastAPI).

Endpoints:
  GET    /                        — Web UI
  POST   /pack                    — Upload APK → start async job → return job_id
  GET    /jobs/{job_id}/stream    — SSE progress stream
  GET    /jobs/{job_id}           — Poll job status
  GET    /apps/{app_id}/download  — Download the packed APK
  GET    /apps                    — List all packed apps
  DELETE /apps/{app_id}           — Delete a packed app
"""

import asyncio
import json
import logging
import os
import re
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session

from fuin import config
from server.database import App, init_db, make_engine, make_get_session
from server.jobs import JobStatus, create_job, get_job
from server.models import AppInfo, PackResult
from server.pipeline import analyze_apk, run_pipeline

log = logging.getLogger(__name__)

_engine = make_engine(config.DATABASE_URL)
get_session = make_get_session(_engine)

_STATIC_DIR = Path(__file__).parent / "static"


def _safe_package_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._\\-]", "_", name) or "unknown"


def verify_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = None,  # query param fallback for SSE (EventSource can't set headers)
):
    provided = x_api_key or api_key
    if not config.ADMIN_API_KEY or provided != config.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not config.ADMIN_API_KEY:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
    init_db(_engine)
    yield


app = FastAPI(title="fuin Packer Server", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    html_path = _STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return HTMLResponse(html_path.read_text())


@app.post("/pack", dependencies=[Depends(verify_api_key)])
async def pack_apk(
    file: UploadFile = File(...),
    app_class: str = Form(default=""),
):
    """Upload APK → start background job → return job_id immediately."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")

    apk_bytes = await file.read()
    job = create_job()

    async def _run() -> None:
        tmp_path: str | None = None
        try:
            job.status = JobStatus.running

            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(apk_bytes)
                tmp_path = tmp.name

            loop = asyncio.get_event_loop()
            analysis = await loop.run_in_executor(None, analyze_apk, tmp_path)

            if not analysis["has_classes_dex"]:
                raise ValueError("APK does not contain classes.dex")

            def _progress(step: str, pct: int) -> None:
                job.progress_step = step
                job.progress_pct = pct
                job.push({"status": "running", "step": step, "pct": pct})

            packed_path, apk_sig = await loop.run_in_executor(
                None,
                lambda: run_pipeline(tmp_path, app_class=app_class or None, progress=_progress),
            )

            def _save():
                entry = App(
                    package_name=analysis["package_name"],
                    apk_signature=apk_sig,
                    packed_apk_path=packed_path,
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
            ).model_dump()

            job.result = result
            job.status = JobStatus.done
            job.push({"status": JobStatus.done, "step": "done", "pct": 100, "result": result})
            log.info("packed app_id=%s package=%s", entry.app_id, entry.package_name)

        except Exception as exc:
            log.exception("pack job %s failed", job.job_id)
            job.status = JobStatus.error
            job.error = str(exc)
            job.push({"status": JobStatus.error, "step": "error", "pct": 0, "error": str(exc)})
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


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
def get_job_status(job_id: str):
    """Poll-based job status check."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job.job_id,
        "status": job.status,
        "step": job.progress_step,
        "pct": job.progress_pct,
        "result": job.result,
        "error": job.error,
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


@app.get("/apps", response_model=list[AppInfo], dependencies=[Depends(verify_api_key)])
def list_apps(db: Session = Depends(get_session)):
    return [
        AppInfo(
            app_id=a.app_id,
            package_name=a.package_name,
            apk_signature=a.apk_signature,
        )
        for a in db.query(App).all()
    ]


@app.delete("/apps/{app_id}", dependencies=[Depends(verify_api_key)])
def delete_app(app_id: str, db: Session = Depends(get_session)):
    entry = db.get(App, app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="App not found")
    if entry.packed_apk_path and os.path.exists(entry.packed_apk_path):
        os.unlink(entry.packed_apk_path)
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
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=False)
