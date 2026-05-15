import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class WatchTarget(Base):
    __tablename__ = "watch_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), unique=True, nullable=False)
    target_type = Column(String(50), nullable=False)  # domain, email
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scanned_at = Column(DateTime, nullable=True)


class ExposedCredential(Base):
    __tablename__ = "exposed_credentials"

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
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    hash = Column(String(64), unique=True, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    source_feed = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    sent = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class FeedStatus(Base):
    __tablename__ = "feed_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(String(100), unique=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(50), nullable=True)
    last_error = Column(Text, nullable=True)
    total_results = Column(Integer, default=0)


_engine = None
_SessionLocal = None


def init_db(config: dict) -> None:
    global _engine, _SessionLocal

    db_url = config.get("database", {}).get("url")
    if not db_url:
        sqlite_path = config.get("database", {}).get("sqlite_path", "wraith.db")
        db_url = f"sqlite:///{sqlite_path}"

    _engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine)
    logger.info(f"Database initialized: {db_url}")


def get_db() -> Session:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _SessionLocal()
