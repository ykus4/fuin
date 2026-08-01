"""Packed-app listing, downloads, ProGuard mapping and deletion."""

import logging
import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from fuin.server.config import get_server_settings
from fuin.server.deps import Apps, CurrentApp, verify_api_key
from fuin.server.schemas import AppInfo, MappingUploaded, StatusResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/apps", dependencies=[Depends(verify_api_key)])


def _safe_package_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._\-]", "_", name) or "unknown"


@router.get("", response_model=list[AppInfo])
def list_apps(apps: Apps):
    return [
        AppInfo(
            app_id=a.app_id,
            package_name=a.package_name,
            apk_signature=a.apk_signature,
            analysis=a.analysis,
            has_mapping=bool(a.mapping_path and os.path.exists(a.mapping_path)),
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in apps.list_newest_first()
    ]


@router.get("/{app_id}/download")
def download_packed_apk(entry: CurrentApp):
    if not entry.packed_apk_path or not os.path.exists(entry.packed_apk_path):
        raise HTTPException(status_code=404, detail="Packed APK not found on disk")
    return FileResponse(
        entry.packed_apk_path,
        media_type="application/vnd.android.package-archive",
        filename=f"{_safe_package_name(entry.package_name)}_packed.apk",
    )


@router.post("/{app_id}/mapping/upload", response_model=MappingUploaded)
async def upload_mapping(entry: CurrentApp, apps: Apps, file: UploadFile = File(...)):
    settings = get_server_settings()
    content = await file.read()
    if len(content) > settings.max_mapping_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Mapping file too large (max {settings.max_mapping_bytes // (1024 * 1024)} MB)",
        )

    mapping_dir = Path(settings.packed_apk_dir) / "mappings"
    mapping_dir.mkdir(parents=True, exist_ok=True)
    mapping_path = mapping_dir / f"{entry.app_id}_mapping.txt"
    mapping_path.write_bytes(content)

    apps.set_mapping_path(entry, str(mapping_path))
    apps.session.commit()
    return MappingUploaded(status="uploaded", app_id=entry.app_id, size_bytes=len(content))


@router.get("/{app_id}/mapping")
def download_mapping(entry: CurrentApp):
    if not entry.mapping_path or not os.path.exists(entry.mapping_path):
        raise HTTPException(status_code=404, detail="No mapping file for this app")
    return FileResponse(
        entry.mapping_path,
        media_type="text/plain",
        filename=f"{_safe_package_name(entry.package_name)}_mapping.txt",
    )


@router.delete("/{app_id}", response_model=StatusResponse)
def delete_app(entry: CurrentApp, apps: Apps):
    app_id = entry.app_id
    apps.delete(entry)
    apps.session.commit()
    log.info("deleted app_id=%s", app_id)
    return StatusResponse(status="deleted")
