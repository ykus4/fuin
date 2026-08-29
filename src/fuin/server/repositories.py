"""Data access for apps and job records.

Every ORM query lives here. Previously sessions were opened and queried in
three layers with three different idioms — routes via the ``get_db``
dependency, one route via the raw engine, and services constructing their own
``Session(engine)`` — which left the services untestable against an injected
transaction.

Repositories take a ``Session``; deciding where that session comes from is the
caller's job.
"""

import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from fuin.server.database import App, AppWebhook, JobRecord

log = logging.getLogger(__name__)


def try_unlink(path: str | None) -> None:
    """Delete a file if it is there, logging rather than raising on failure."""
    if not path or not os.path.exists(path):
        return
    try:
        os.unlink(path)
    except OSError as e:
        log.warning("could not delete %s: %s", path, e)


class AppRepository:
    """Reads and writes for packed-app rows and their files."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, app_id: str) -> App | None:
        return self.session.get(App, app_id)

    def list_newest_first(self) -> list[App]:
        return self.session.query(App).order_by(App.created_at.desc()).all()

    def add(self, app: App, webhook_urls: list[str] | None = None) -> App:
        """Insert an app and its webhook rows. Flushes to populate ``app_id``."""
        self.session.add(app)
        self.session.flush()
        for url in webhook_urls or []:
            self.session.add(AppWebhook(app_id=app.app_id, url=url))
        return app

    def set_mapping_path(self, app: App, path: str) -> None:
        app.mapping_path = path

    def delete(self, app: App) -> None:
        """Delete the row and the files it owns."""
        try_unlink(app.packed_apk_path)
        try_unlink(app.mapping_path)
        self.session.delete(app)

    def delete_older_than(self, days: int) -> int:
        """Delete apps created more than ``days`` ago. Returns the row count."""
        cutoff = datetime.now(UTC) - timedelta(days=days)
        old = self.session.query(App).filter(App.created_at < cutoff).all()
        for app in old:
            self.delete(app)
        return len(old)


class JobRepository:
    """Reads and writes for the durable job records behind the in-memory store."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, job_id: str) -> JobRecord | None:
        return self.session.get(JobRecord, job_id)

    def create(self, job_id: str, status: str = "pending") -> JobRecord:
        record = JobRecord(job_id=job_id, status=status)
        self.session.add(record)
        return record

    def update(self, job_id: str, **fields) -> None:
        record = self.get(job_id)
        if record is None:
            return
        for key, value in fields.items():
            setattr(record, key, value)

    def delete_older_than(self, days: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        old = self.session.query(JobRecord).filter(JobRecord.created_at < cutoff).all()
        for record in old:
            self.session.delete(record)
        return len(old)

    def fail_unfinished(self, reason: str) -> int:
        """Mark every still-running job as failed. Returns the row count.

        The in-memory job store does not survive a restart, so rows left at
        "running" describe work nothing is doing — and ``GET /jobs/{id}``
        reports them as in progress forever.
        """
        stranded = (
            self.session.query(JobRecord).filter(JobRecord.status.in_(("pending", "running"))).all()
        )
        for record in stranded:
            record.status = "error"
            record.error = reason
            record.finished_at = datetime.now(UTC)
        return len(stranded)
