"""
In-memory job store for async pack jobs.

Jobs are keyed by job_id (UUID). Consumers poll via asyncio.Queue per job.

The store is process-local and bounded: it keeps at most :data:`MAX_JOBS`
entries, evicting the oldest finished jobs first. Terminal state also lives in
the ``jobs`` table, so evicting a completed job only costs the SSE stream —
status remains available via the DB fallback.
"""

import asyncio
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

MAX_JOBS = 512


class JobStatus(StrEnum):
    pending = "pending"
    running = "running"
    done = "done"
    error = "error"


@dataclass
class Job:
    job_id: str
    status: JobStatus = JobStatus.pending
    progress_step: str = ""
    progress_pct: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    # SSE subscribers receive events from this queue
    _queue: asyncio.Queue = field(default_factory=asyncio.Queue, repr=False)

    def push(self, event: dict) -> None:
        self._queue.put_nowait(event)

    async def stream(self):
        """Async generator that yields events until the job finishes."""
        while True:
            event = await self._queue.get()
            yield event
            if event.get("status") in (JobStatus.done, JobStatus.error):
                break


_jobs: OrderedDict[str, Job] = OrderedDict()


def _evict() -> None:
    """Drop finished jobs, oldest first, until the store is back under cap."""
    while len(_jobs) > MAX_JOBS:
        for job_id, job in _jobs.items():
            if job.status in (JobStatus.done, JobStatus.error):
                del _jobs[job_id]
                break
        else:
            # Nothing finished to reclaim; the cap gives way rather than
            # dropping a job that is still running.
            return


def create_job() -> Job:
    job_id = str(uuid.uuid4())
    job = Job(job_id=job_id)
    _jobs[job_id] = job
    _evict()
    return job


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)


def reset_jobs() -> None:
    """Drop every tracked job. Test-only helper."""
    _jobs.clear()
