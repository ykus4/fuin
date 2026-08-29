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
        """Queue an event. Only safe to call from the event loop's own thread."""
        self._queue.put_nowait(event)

    def push_threadsafe(self, loop: asyncio.AbstractEventLoop, event: dict) -> None:
        """Queue an event from a worker thread.

        ``asyncio.Queue`` is not thread-safe: ``put_nowait`` resolves waiter
        futures directly, so calling it off-loop races with the loop and leaves
        the SSE consumer unwoken. The pack pipeline runs in an executor, so
        every progress event arrives on the wrong thread.
        """
        loop.call_soon_threadsafe(self.push, event)

    async def stream(self):
        """Async generator that yields events until the job finishes.

        A subscriber that arrives after the job ended would otherwise wait on a
        queue nothing will ever fill, so terminal state is replayed first.
        """
        if self.status in (JobStatus.done, JobStatus.error):
            yield self.snapshot()
            return

        while True:
            event = await self._queue.get()
            yield event
            if event.get("status") in (JobStatus.done, JobStatus.error):
                break

    def snapshot(self) -> dict[str, Any]:
        """The job's current state as an SSE event."""
        event: dict[str, Any] = {
            "status": self.status,
            "step": self.progress_step or self.status,
            "pct": self.progress_pct,
        }
        if self.result is not None:
            event["result"] = self.result
        if self.error is not None:
            event["error"] = self.error
        return event


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
