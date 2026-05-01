"""
fuin Packer Server (FastAPI).

Endpoints:
  POST   /pack                   — Upload APK → pack → return app_id
  GET    /apps/{app_id}/download — Download the packed APK
  GET    /apps                   — List all packed apps
  DELETE /apps/{app_id}          — Delete a packed app
"""

import logging
import os
import re
import tempfile
from contextlib import asynccontextmanager

from database import App, init_db, make_engine, make_get_session
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from models import AppInfo, PackResult
from pipeline import analyze_apk, run_pipeline
from sqlalchemy.orm import Session

from fuin import config

log = logging.getLogger(__name__)

_engine = make_engine(config.DATABASE_URL)
get_session = make_get_session(_engine)


def _safe_package_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._\-]", "_", name) or "unknown"


def verify_api_key(x_api_key: str = Header(...)):
    if not config.ADMIN_API_KEY or x_api_key != config.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not config.ADMIN_API_KEY:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
    init_db(_engine)
    yield


app = FastAPI(title="fuin Packer Server", lifespan=lifespan)


@app.post("/pack", response_model=PackResult, dependencies=[Depends(verify_api_key)])
async def pack_apk(
    file: UploadFile = File(...),
    app_class: str = Form(default=""),
    db: Session = Depends(get_session),
):
    """Upload a raw APK → analyze → encrypt DEX → sign → return app_id for download."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        analysis = analyze_apk(tmp_path)

        if not analysis["has_classes_dex"]:
            raise HTTPException(status_code=422, detail="APK does not contain classes.dex")

        packed_path, apk_sig = run_pipeline(tmp_path, app_class=app_class or None)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    entry = App(
        package_name=analysis["package_name"],
        apk_signature=apk_sig,
        packed_apk_path=packed_path,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    log.info("packed app_id=%s package=%s", entry.app_id, entry.package_name)
    return PackResult(
        app_id=entry.app_id,
        package_name=entry.package_name,
        apk_signature=apk_sig,
        analysis=analysis,
    )


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
