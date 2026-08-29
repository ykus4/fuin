"""SQLite-backed storage for packed APKs, job history, and per-app webhooks.

Uses SQLAlchemy 2.0 ``Mapped[...]`` annotations rather than bare ``Column``
assignments, so attribute access is typed as the underlying Python value
instead of ``Column[str]``.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    create_engine,
    event,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class App(Base):
    __tablename__ = "apps"

    app_id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name: Mapped[str] = mapped_column(String, nullable=False)
    apk_signature: Mapped[str] = mapped_column(String, nullable=False)
    packed_apk_path: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    mapping_path: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.now())

    webhooks: Mapped[list["AppWebhook"]] = relationship(
        back_populates="app",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    jobs: Mapped[list["JobRecord"]] = relationship(back_populates="app", passive_deletes=True)

    __table_args__ = (Index("ix_apps_created_at", "created_at"),)


class AppWebhook(Base):
    """Webhook URLs registered per packed app (notified on pack completion)."""

    __tablename__ = "app_webhooks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    app_id: Mapped[str] = mapped_column(
        ForeignKey("apps.app_id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String, nullable=False)

    app: Mapped["App"] = relationship(back_populates="webhooks")

    __table_args__ = (Index("ix_app_webhooks_app_id", "app_id"),)


class JobRecord(Base):
    """Persisted job history so records survive server restarts."""

    __tablename__ = "jobs"

    job_id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    progress_step: Mapped[str | None] = mapped_column(String, nullable=True)
    progress_pct: Mapped[int | None] = mapped_column(nullable=True, default=0)
    app_id: Mapped[str | None] = mapped_column(
        ForeignKey("apps.app_id", ondelete="SET NULL"), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    app: Mapped["App | None"] = relationship(back_populates="jobs")

    __table_args__ = (Index("ix_jobs_created_at", "created_at"),)


def make_engine(database_url: str):
    """Build the engine, applying SQLite-specific settings only to SQLite.

    ``check_same_thread`` is a SQLite connect argument; passing it to any other
    driver is a TypeError, which made FUIN_DATABASE_URL SQLite-only in practice
    despite being documented as any SQLAlchemy URL.
    """
    if not database_url.startswith("sqlite"):
        return create_engine(database_url)

    engine = create_engine(database_url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _record):
        # WAL lets the progress writes from a pack job proceed while a request
        # reads; busy_timeout turns the remaining contention into a short wait
        # instead of an immediate "database is locked".
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine


def init_db(engine) -> None:
    """Create tables if they do not exist (for fresh installs / tests).

    Production deployments should rely on Alembic migrations instead.
    """
    Base.metadata.create_all(bind=engine)
