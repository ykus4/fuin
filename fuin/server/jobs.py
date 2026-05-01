"""
In-memory job store for async pack jobs.

Jobs are keyed by job_id (UUID). Consumers poll via asyncio.Queue per job.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


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


_jobs: dict[str, Job] = {}


def create_job() -> Job:
    job_id = str(uuid.uuid4())
    job = Job(job_id=job_id)
    _jobs[job_id] = job
    return job


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)
