"""Analyze and pack endpoints."""

import asyncio
import os
import tempfile

from fastapi import APIRouter, Depends, File, Form, UploadFile

from fuin.server import pipeline
from fuin.server.background import spawn
from fuin.server.deps import Jobs, get_engine, verify_api_key
from fuin.server.jobs import create_job
from fuin.server.routers.uploads import read_apk_upload
from fuin.server.schemas import JobAccepted
from fuin.server.services.pack_service import run_pack_job

router = APIRouter(dependencies=[Depends(verify_api_key)])


@router.post("/analyze")
async def analyze_apk_targets(file: UploadFile = File(...)):
    apk_bytes = await read_apk_upload(file)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name

    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, pipeline.analyze_targets, tmp_path)
    finally:
        os.unlink(tmp_path)


@router.post("/pack", response_model=JobAccepted)
async def pack_apk(
    jobs: Jobs,
    file: UploadFile = File(...),
    app_class: str = Form(default=""),
    webhook_url: str = Form(default=""),
    exclude_files: str = Form(default=""),
    encrypt_native: bool = Form(default=True),
    encrypt_assets: bool = Form(default=True),
    # Omitting these defers to the corresponding FUIN_* setting; see PackOptions.
    encrypt_strings: bool | None = Form(default=None),
    root_detection: bool | None = Form(default=None),
    emulator_detection: bool | None = Form(default=None),
):
    apk_bytes = await read_apk_upload(file)

    job = create_job()
    jobs.create(job.job_id)
    jobs.session.commit()

    spawn(
        run_pack_job(
            get_engine(),
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
    return JobAccepted(job_id=job.job_id)
