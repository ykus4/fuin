"""Orchestrates a single packing job: runs the pipeline in a worker thread,
persists results to the database, and dispatches webhooks.
"""

import asyncio
import contextlib
import logging
import os
import tempfile
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from fuin.server.config import get_server_settings
from fuin.server.database import App
from fuin.server.jobs import Job, JobStatus
from fuin.server.pipeline import PackOptions, analyze_apk, run_pipeline
from fuin.server.repositories import AppRepository, JobRepository
from fuin.server.schemas import PackedApp
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
    fields: dict[str, Any] = {}
    if status:
        fields["status"] = status
    if step:
        fields["progress_step"] = step
    if pct is not None:
        fields["progress_pct"] = pct
    if app_id:
        fields["app_id"] = app_id
    if error:
        fields["error"] = error
    if status in ("done", "error"):
        fields["finished_at"] = datetime.now(UTC)

    try:
        with Session(engine) as session:
            JobRepository(session).update(job_id, **fields)
            session.commit()
    except Exception as e:
        log.warning("failed to update job record %s: %s", job_id, e)


def _save_app(
    engine, *, analysis: dict, apk_sig: str, packed_path: str, webhook_urls: list[str]
) -> App:
    with Session(engine) as session:
        entry = App(
            package_name=analysis.get("package_name", "unknown"),
            apk_signature=apk_sig,
            packed_apk_path=packed_path,
            analysis=analysis,
        )
        AppRepository(session).add(entry, webhook_urls)
        session.commit()
        session.refresh(entry)
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
    encrypt_strings: bool | None,
    root_detection: bool | None,
    emulator_detection: bool | None,
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

        loop = asyncio.get_running_loop()
        analysis = await loop.run_in_executor(None, analyze_apk, tmp_path)

        if not analysis.get("has_classes_dex"):
            raise ValueError("APK does not contain classes.dex")

        def _on_progress(step: str, pct: int) -> None:
            # Called from the executor thread, so the queue write has to be
            # marshalled back onto the loop.
            job.progress_step = step
            job.progress_pct = pct
            job.push_threadsafe(loop, {"status": "running", "step": step, "pct": pct})
            update_job_record(engine, job.job_id, status="running", step=step, pct=pct)

        options = PackOptions(
            encrypt_native=encrypt_native,
            encrypt_assets=encrypt_assets,
            encrypt_strings=encrypt_strings,
            root_detection=root_detection,
            emulator_detection=emulator_detection,
            exclude_files=exclude_files,
        )

        packed = await loop.run_in_executor(
            None,
            lambda: run_pipeline(
                tmp_path,
                app_class=app_class or None,
                progress=_on_progress,
                options=options,
            ),
        )

        webhook_urls = webhook_service.parse_urls(webhook_url, get_server_settings().webhook_url)
        entry = await loop.run_in_executor(
            None,
            lambda: _save_app(
                engine,
                analysis=analysis,
                apk_sig=packed.sha256,
                packed_path=packed.path,
                webhook_urls=webhook_urls,
            ),
        )

        result: dict[str, Any] = PackedApp(
            app_id=entry.app_id,
            package_name=entry.package_name,
            apk_signature=packed.sha256,
            analysis=analysis,
            report=packed.report,
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
        message = _client_safe_error(exc)
        job.status = JobStatus.error
        job.error = message
        job.push({"status": JobStatus.error, "step": "error", "pct": 0, "error": message})
        update_job_record(engine, job.job_id, status="error", error=message)
    finally:
        if tmp_path:
            await asyncio.to_thread(_remove_quietly, tmp_path)


def _remove_quietly(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _client_safe_error(exc: Exception) -> str:
    """What the client is told a failure was.

    ``str(exc)`` on an OSError carries the server's temp and keystore paths,
    and that string is served verbatim by ``GET /jobs/{id}``. The full
    exception is already in the log with its traceback.
    """
    if isinstance(exc, ValueError):
        # Raised deliberately by the packer for bad input — safe and useful.
        return str(exc)
    return f"{type(exc).__name__} while packing; see the server log for details"
