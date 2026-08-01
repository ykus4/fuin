"""Job status: SSE stream and polling fallback."""

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from fuin.server.deps import Apps, Jobs, verify_api_key
from fuin.server.jobs import get_job
from fuin.server.schemas import JobStatus

router = APIRouter(prefix="/jobs", dependencies=[Depends(verify_api_key)])


@router.get("/{job_id}/stream")
async def stream_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def _sse():
        async for event in job.stream():
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(_sse(), media_type="text/event-stream")


@router.get("/{job_id}", response_model=JobStatus)
def get_job_status(job_id: str, jobs: Jobs, apps: Apps):
    """Poll-based status, falling back to the DB for jobs the process has evicted."""
    job = get_job(job_id)
    if job:
        return JobStatus(
            job_id=job.job_id,
            status=job.status,
            step=job.progress_step,
            pct=job.progress_pct,
            result=job.result,
            error=job.error,
        )

    record = jobs.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Job not found")

    result = None
    if record.app_id:
        entry = apps.get(record.app_id)
        if entry:
            result = {
                "app_id": entry.app_id,
                "package_name": entry.package_name,
                "apk_signature": entry.apk_signature,
                "analysis": entry.analysis or {},
            }
    return JobStatus(
        job_id=record.job_id,
        status=record.status,
        step=record.progress_step or "",
        pct=record.progress_pct or 0,
        result=result,
        error=record.error,
    )
