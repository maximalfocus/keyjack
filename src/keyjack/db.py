"""Database engine and session wiring (SQLite via SQLAlchemy 2.0)."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings


def make_engine(settings: Settings) -> Engine:
    connect_args: dict[str, object] = {}
    if settings.db_url.startswith("sqlite"):
        # FastAPI serves requests from a threadpool; allow cross-thread use of the
        # single local SQLite connection. State is process-local and ephemeral.
        connect_args["check_same_thread"] = False
    return create_engine(settings.db_url, connect_args=connect_args, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
