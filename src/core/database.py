import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    Boolean, Column, DateTime, Index, Integer, String, Text, create_engine, event
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-naive datetime (for DB compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class WatchTarget(Base):
    __tablename__ = "watch_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), unique=True, nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # domain, email
    active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=_utcnow)
    last_scanned_at = Column(DateTime, nullable=True)


class ExposedCredential(Base):
    __tablename__ = "exposed_credentials"
    __table_args__ = (
        Index("ix_ec_target", "target"),
        Index("ix_ec_severity", "severity"),
        Index("ix_ec_source_feed", "source_feed"),
        Index("ix_ec_first_seen_at", "first_seen_at"),
        Index("ix_ec_target_severity", "target", "severity"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    source_feed = Column(String(100), nullable=False)
    exposure_type = Column(String(100), nullable=False)  # email, password, hash, paste, secret
    value = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    breach_name = Column(String(255), nullable=True)
    breach_date = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    raw = Column(Text, nullable=True)
    first_seen_at = Column(DateTime, default=_utcnow)
    hash = Column(String(64), unique=True, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_target", "target"),
        Index("ix_alert_created_at", "created_at"),
        Index("ix_alert_sent", "sent"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    source_feed = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    sent = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class FeedStatus(Base):
    __tablename__ = "feed_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(String(100), unique=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(50), nullable=True)
    last_error = Column(Text, nullable=True)
    total_results = Column(Integer, default=0)


class InvestigationNote(Base):
    """Analyst notes attached to a specific finding or target."""

    __tablename__ = "investigation_notes"
    __table_args__ = (
        Index("ix_note_finding_id", "finding_id"),
        Index("ix_note_target", "target"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, nullable=True)  # NULL = target-level note
    target = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class SavedSearch(Base):
    """Persisted filter sets for quick dashboard access."""

    __tablename__ = "saved_searches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    filters = Column(Text, nullable=False)  # JSON-serialized filter dict
    created_at = Column(DateTime, default=_utcnow)


_engine = None
_SessionLocal = None


def init_db(config: dict) -> None:
    global _engine, _SessionLocal

    db_url = config.get("database", {}).get("url")
    if not db_url:
        sqlite_path = config.get("database", {}).get("sqlite_path", "wraith.db")
        db_url = f"sqlite:///{sqlite_path}"

    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_engine(db_url, echo=False, connect_args=connect_args)

    # Enable WAL mode for SQLite to improve concurrent read/write performance
    if db_url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine)

    # Log without exposing credentials embedded in the URL
    safe_url = db_url.split("@")[-1] if "@" in db_url else db_url
    logger.info("Database initialized: %s", safe_url)


def get_db() -> Session:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _SessionLocal()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager that auto-closes the session."""
    session = get_db()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
