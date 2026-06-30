"""Periodic / on-startup cleanup of stale packed APKs and job records."""

import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from fuin import config
from fuin.server.database import App, JobRecord

log = logging.getLogger(__name__)


def _try_unlink(path: str | None) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError as e:
        log.warning("could not delete %s: %s", path, e)


def cleanup_old_records(engine) -> int:
    """Delete apps and their files older than CLEANUP_OLDER_THAN_DAYS.

    Returns the number of App rows deleted.
    """
    if not config.CLEANUP_OLDER_THAN_DAYS:
        return 0

    cutoff = datetime.now(UTC) - timedelta(days=config.CLEANUP_OLDER_THAN_DAYS)
    with Session(engine) as s:
        old_apps = s.query(App).filter(App.created_at < cutoff).all()
        for app in old_apps:
            _try_unlink(app.packed_apk_path)
            _try_unlink(app.mapping_path)
            s.delete(app)
        deleted = len(old_apps)

        for jr in s.query(JobRecord).filter(JobRecord.created_at < cutoff).all():
            s.delete(jr)
        s.commit()

    if deleted:
        log.info("cleanup: deleted %d old packed apps", deleted)
    return deleted
