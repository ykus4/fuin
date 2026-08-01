"""FastAPI dependencies: shared engine, session, repositories, API key auth.

The engine is built lazily on first use, so a test setup only has to point
``FUIN_DATABASE_URL`` somewhere else and call :func:`reset_engine`.
"""

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
    """Drop the cached engine so the next call rebuilds it from the environment."""
    global _engine
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
    if not expected or provided != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
