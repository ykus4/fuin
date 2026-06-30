"""FastAPI dependencies: shared engine, session, API key auth.

The engine is built lazily so that test setups can override
``FUIN_DATABASE_URL`` via :func:`importlib.reload` on :mod:`fuin.config`.
"""

from collections.abc import Generator

from fastapi import Header, HTTPException
from sqlalchemy.orm import Session

from fuin import config
from fuin.server.database import init_db, make_engine

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = make_engine(config.DATABASE_URL)
        init_db(_engine)
    return _engine


def reset_engine() -> None:
    """Drop the cached engine. Test-only helper for fixtures that reload config."""
    global _engine
    _engine = None


def get_db() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session


def verify_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = None,  # query-string fallback for SSE (EventSource cannot set headers)
) -> None:
    provided = x_api_key or api_key
    if not config.ADMIN_API_KEY or provided != config.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
