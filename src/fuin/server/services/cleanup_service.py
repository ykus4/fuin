"""On-startup cleanup of stale packed APKs and job records."""

import logging

from sqlalchemy.orm import Session

from fuin.server.config import get_server_settings
from fuin.server.repositories import AppRepository, JobRepository

log = logging.getLogger(__name__)


def cleanup_old_records(engine) -> int:
    """Delete apps and their files older than FUIN_CLEANUP_DAYS.

    Returns the number of App rows deleted. Deletion semantics — including
    unlinking the packed APK and mapping — live in AppRepository.delete, so
    this and the DELETE /apps/{id} route cannot drift apart.
    """
    older_than_days = get_server_settings().cleanup_older_than_days
    if not older_than_days:
        return 0

    with Session(engine) as session:
        deleted = AppRepository(session).delete_older_than(older_than_days)
        JobRepository(session).delete_older_than(older_than_days)
        session.commit()

    if deleted:
        log.info("cleanup: deleted %d old packed apps", deleted)
    return deleted


def fail_stranded_jobs(engine) -> int:
    """Fail jobs left running by a previous process. Returns the row count."""
    with Session(engine) as session:
        stranded = JobRepository(session).fail_unfinished("server restarted while packing")
        session.commit()

    if stranded:
        log.warning("marked %d job(s) as failed: no worker survived the restart", stranded)
    return stranded
