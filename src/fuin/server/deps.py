"""FastAPI dependencies: shared engine, session, repositories, API key auth.

The engine is built lazily on first use, so a test setup only has to point
``FUIN_DATABASE_URL`` somewhere else and call :func:`reset_engine`.
"""

import secrets
from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Path
from sqlalchemy.orm import Session

from fuin.server.config import get_server_settings
from fuin.server.database import App, init_db, make_engine
from fuin.server.repositories import AppRepository, JobRepository

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = make_engine(get_server_settings().database_url)
        init_db(_engine)
    return _engine


def reset_engine() -> None:
    """Drop the cached engine so the next call rebuilds it from the environment.

    Disposes the connection pool first — dropping the reference alone leaks
    every pooled connection, which showed up as ResourceWarnings once the
    test suite started surfacing them.
    """
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def get_db() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]


def get_app_repo(db: DbSession) -> AppRepository:
    return AppRepository(db)


def get_job_repo(db: DbSession) -> JobRepository:
    return JobRepository(db)


Apps = Annotated[AppRepository, Depends(get_app_repo)]
Jobs = Annotated[JobRepository, Depends(get_job_repo)]


def get_app_or_404(app_id: Annotated[str, Path()], apps: Apps) -> App:
    """Resolve an app id, or 404.

    This preamble was copy-pasted into four handlers; as a dependency it also
    keeps the error message consistent.
    """
    entry = apps.get(app_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="App not found")
    return entry


CurrentApp = Annotated[App, Depends(get_app_or_404)]


def verify_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = None,  # query-string fallback for SSE (EventSource cannot set headers)
) -> None:
    provided = x_api_key or api_key
    expected = get_server_settings().admin_api_key
    if not expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
    # compare_digest, not ==: a plain comparison returns as soon as two bytes
    # differ, which leaks the key one character at a time to anyone who can
    # time the response.
    if not secrets.compare_digest(provided or "", expected):
        raise HTTPException(status_code=401, detail="Invalid API key")
