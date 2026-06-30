"""Orchestrates a single packing job: runs the pipeline in a worker thread,
persists results to the database, and dispatches webhooks.
"""

import asyncio
import logging
import os
import tempfile
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from fuin import config
from fuin.server.database import App, AppWebhook, JobRecord
from fuin.server.jobs import Job, JobStatus
from fuin.server.models import PackResult
from fuin.server.pipeline import PipelineOptions, analyze_apk, run_pipeline
from fuin.server.services import webhook_service

log = logging.getLogger(__name__)


def update_job_record(
    engine,
    job_id: str,
    *,
    status: str | None = None,
    step: str | None = None,
    pct: int | None = None,
    app_id: str | None = None,
    error: str | None = None,
) -> None:
    """Update a JobRecord row. Swallows DB errors so they cannot kill the pack job."""
    try:
        with Session(engine) as s:
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
    except Exception as e:
        log.warning("failed to update job record %s: %s", job_id, e)


def _save_app(
    engine, *, analysis: dict, apk_sig: str, packed_path: str, webhook_urls: list[str]
) -> App:
    with Session(engine) as s:
        entry = App(
            package_name=analysis.get("package_name", "unknown"),
            apk_signature=apk_sig,
            packed_apk_path=packed_path,
            analysis=analysis,
        )
        s.add(entry)
        s.flush()  # populate entry.app_id
        for url in webhook_urls:
            s.add(AppWebhook(app_id=entry.app_id, url=url))
        s.commit()
        s.refresh(entry)
        return entry


async def run_pack_job(
    engine,
    job: Job,
    apk_bytes: bytes,
    *,
    app_class: str,
    webhook_url: str,
    encrypt_native: bool,
    encrypt_assets: bool,
    encrypt_strings: bool,
    root_detection: bool,
    emulator_detection: bool,
    exclude_files: tuple[str, ...],
) -> None:
    """Run the pack pipeline asynchronously and persist results."""
    tmp_path: str | None = None
    try:
        job.status = JobStatus.running
        update_job_record(engine, job.job_id, status="running")

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        loop = asyncio.get_event_loop()
        analysis = await loop.run_in_executor(None, analyze_apk, tmp_path)

        if not analysis.get("has_classes_dex"):
            raise ValueError("APK does not contain classes.dex")

        def _on_progress(step: str, pct: int) -> None:
            job.progress_step = step
            job.progress_pct = pct
            job.push({"status": "running", "step": step, "pct": pct})
            update_job_record(engine, job.job_id, status="running", step=step, pct=pct)

        options = PipelineOptions(
            encrypt_native=encrypt_native,
            encrypt_assets=encrypt_assets,
            encrypt_strings=encrypt_strings,
            root_detection=root_detection,
            emulator_detection=emulator_detection,
            exclude_files=exclude_files,
        )

        packed_path, apk_sig, pack_report = await loop.run_in_executor(
            None,
            lambda: run_pipeline(
                tmp_path,
                app_class=app_class or None,
                progress=_on_progress,
                options=options,
            ),
        )

        webhook_urls = webhook_service.parse_urls(webhook_url, config.WEBHOOK_URL)
        entry = await loop.run_in_executor(
            None,
            lambda: _save_app(
                engine,
                analysis=analysis,
                apk_sig=apk_sig,
                packed_path=packed_path,
                webhook_urls=webhook_urls,
            ),
        )

        result: dict[str, Any] = PackResult(
            app_id=entry.app_id,
            package_name=entry.package_name,
            apk_signature=apk_sig,
            analysis=analysis,
            report=pack_report,
        ).model_dump()

        job.result = result
        job.status = JobStatus.done
        job.push({"status": JobStatus.done, "step": "done", "pct": 100, "result": result})
        update_job_record(
            engine, job.job_id, status="done", step="done", pct=100, app_id=entry.app_id
        )
        log.info("packed app_id=%s package=%s", entry.app_id, entry.package_name)

        webhook_service.fire(webhook_urls, {"event": "pack.done", "result": result})

    except Exception as exc:
        log.exception("pack job %s failed", job.job_id)
        job.status = JobStatus.error
        job.error = str(exc)
        job.push({"status": JobStatus.error, "step": "error", "pct": 0, "error": str(exc)})
        update_job_record(engine, job.job_id, status="error", error=str(exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
