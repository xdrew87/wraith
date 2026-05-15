import pytest
from datetime import datetime


BASE_CONFIG = {
    "database": {"sqlite_path": ":memory:"},
}


class TestDatabase:
    def setup_method(self):
        from core.database import init_db
        import core.database as db_module
        db_module._engine = None
        db_module._SessionLocal = None
        init_db(BASE_CONFIG)

    def test_watch_target_create(self):
        from core.database import get_db, WatchTarget
        db = get_db()
        wt = WatchTarget(target="example.com", target_type="domain", active=True)
        db.add(wt)
        db.commit()
        result = db.query(WatchTarget).filter_by(target="example.com").first()
        assert result is not None
        assert result.active is True
        db.close()

    def test_exposed_credential_create(self):
        from core.database import get_db, ExposedCredential
        db = get_db()
        cred = ExposedCredential(
            target="example.com",
            source_feed="HIBP",
            exposure_type="email_breach",
            value="admin@example.com",
            severity="HIGH",
            hash="unique-hash-001",
        )
        db.add(cred)
        db.commit()
        result = db.query(ExposedCredential).filter_by(hash="unique-hash-001").first()
        assert result is not None
        assert result.severity == "HIGH"
        db.close()

    def test_duplicate_hash_rejected(self):
        from core.database import get_db, ExposedCredential
        from sqlalchemy.exc import IntegrityError
        db = get_db()
        for _ in range(2):
            db.add(ExposedCredential(
                target="example.com",
                source_feed="HIBP",
                exposure_type="test",
                value="x",
                severity="LOW",
                hash="duplicate-hash",
            ))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.close()

    def test_alert_create(self):
        from core.database import get_db, Alert
        db = get_db()
        alert = Alert(
            target="example.com",
            source_feed="HIBP",
            severity="HIGH",
            message="Test alert",
            sent=False,
        )
        db.add(alert)
        db.commit()
        result = db.query(Alert).filter_by(target="example.com").first()
        assert result.message == "Test alert"
        db.close()

    def test_feed_status_create(self):
        from core.database import get_db, FeedStatus
        db = get_db()
        fs = FeedStatus(feed_name="HIBP", last_status="ok", total_results=5)
        db.add(fs)
        db.commit()
        result = db.query(FeedStatus).filter_by(feed_name="HIBP").first()
        assert result.total_results == 5
        db.close()
