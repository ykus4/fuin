"""
SQLite-backed storage for packed APKs and job history.
"""

import uuid
from collections.abc import Generator

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


class App(Base):
    __tablename__ = "apps"

    app_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name = Column(String, nullable=False)
    apk_signature = Column(String, nullable=False)
    packed_apk_path = Column(String, nullable=True)
    # Rich analysis metadata (stored as JSON)
    analysis = Column(JSON, nullable=True)
    # ProGuard mapping file path (if uploaded alongside the APK)
    mapping_path = Column(String, nullable=True)
    # Webhook URLs to notify on completion (comma-separated)
    webhook_urls = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class JobRecord(Base):
    """Persisted job history so records survive server restarts."""

    __tablename__ = "jobs"

    job_id = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="pending")
    progress_step = Column(String, nullable=True)
    progress_pct = Column(Integer, nullable=True, default=0)
    app_id = Column(String, nullable=True)  # set when done
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)


def make_engine(database_url: str):
    return create_engine(database_url, connect_args={"check_same_thread": False})


def init_db(engine) -> None:
    Base.metadata.create_all(bind=engine)


def make_get_session(engine):
    def get_session() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    return get_session
