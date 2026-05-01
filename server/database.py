"""
SQLite-backed storage for packed APKs.
"""

import uuid
from collections.abc import Generator

from sqlalchemy import Column, DateTime, String, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


class App(Base):
    __tablename__ = "apps"

    app_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    package_name = Column(String, nullable=False)
    apk_signature = Column(String, nullable=False)
    packed_apk_path = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


def make_engine(database_url: str):
    return create_engine(database_url, connect_args={"check_same_thread": False})


def init_db(engine) -> None:
    Base.metadata.create_all(bind=engine)


def make_get_session(engine):
    def get_session() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    return get_session
