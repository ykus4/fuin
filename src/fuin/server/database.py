"""SQLite-backed storage for packed APKs, job history, and per-app webhooks."""

import uuid
from collections.abc import Generator

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship


class Base(DeclarativeBase):
    pass


class App(Base):
    __tablename__ = "apps"

    app_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name = Column(String, nullable=False)
    apk_signature = Column(String, nullable=False)
    packed_apk_path = Column(String, nullable=True)
    analysis = Column(JSON, nullable=True)
    mapping_path = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    webhooks = relationship(
        "AppWebhook",
        back_populates="app",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    jobs = relationship("JobRecord", back_populates="app", passive_deletes=True)

    __table_args__ = (Index("ix_apps_created_at", "created_at"),)


class AppWebhook(Base):
    """Webhook URLs registered per packed app (notified on pack completion)."""

    __tablename__ = "app_webhooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    app_id = Column(String, ForeignKey("apps.app_id", ondelete="CASCADE"), nullable=False)
    url = Column(String, nullable=False)

    app = relationship("App", back_populates="webhooks")

    __table_args__ = (Index("ix_app_webhooks_app_id", "app_id"),)


class JobRecord(Base):
    """Persisted job history so records survive server restarts."""

    __tablename__ = "jobs"

    job_id = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="pending")
    progress_step = Column(String, nullable=True)
    progress_pct = Column(Integer, nullable=True, default=0)
    app_id = Column(String, ForeignKey("apps.app_id", ondelete="SET NULL"), nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)

    app = relationship("App", back_populates="jobs")

    __table_args__ = (Index("ix_jobs_created_at", "created_at"),)


def make_engine(database_url: str):
    return create_engine(database_url, connect_args={"check_same_thread": False})


def init_db(engine) -> None:
    """Create tables if they do not exist (for fresh installs / tests).

    Production deployments should rely on Alembic migrations instead.
    """
    Base.metadata.create_all(bind=engine)


def make_get_session(engine):
    def get_session() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    return get_session
