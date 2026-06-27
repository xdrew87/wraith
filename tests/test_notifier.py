import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

BASE_CONFIG = {
    "database": {"sqlite_path": ":memory:"},
    "alerting": {
        "enabled": True,
        "min_severity": "MEDIUM",
        "slack": {"enabled": False, "webhook_url": ""},
        "discord": {"enabled": False, "webhook_url": ""},
        "smtp": {"enabled": False},
    },
    "monitor": {"max_concurrent_feeds": 5},
}

SAMPLE_RESULTS = [
    {
        "target": "example.com",
        "source_feed": "HIBP",
        "exposure_type": "domain_breach",
        "value": "admin@example.com",
        "severity": "HIGH",
        "breach_name": "TestBreach",
        "breach_date": "2023-01-01",
        "description": "Test",
        "raw": "{}",
        "hash": "unique-hash-notifier-test-001",
    }
]

CRITICAL_RESULTS = [
    {
        "target": "example.com",
        "source_feed": "DeHashed",
        "exposure_type": "plaintext_password",
        "value": "admin@example.com:secret123",
        "severity": "CRITICAL",
        "breach_name": "TestDB",
        "breach_date": None,
        "description": "Plaintext password",
        "raw": "{}",
        "hash": "unique-hash-notifier-test-002",
    }
]


@pytest.fixture(autouse=True)
def reset_db():
    import core.database as db_module
    db_module._engine = None
    db_module._SessionLocal = None
    from core.database import init_db
    init_db(BASE_CONFIG)
    yield
    db_module._engine = None
    db_module._SessionLocal = None


class TestQueueAlerts:
    @pytest.mark.asyncio
    async def test_queue_alerts_disabled(self):
        config = dict(BASE_CONFIG)
        config["alerting"] = {"enabled": False}
        from alerting.notifier import queue_alerts
        await queue_alerts("example.com", SAMPLE_RESULTS, config)
        # No exception, no alerts queued
        from core.database import db_session, Alert
        with db_session() as db:
            count = db.query(Alert).count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_queue_alerts_below_min_severity(self):
        config = dict(BASE_CONFIG)
        config["alerting"] = {"enabled": True, "min_severity": "CRITICAL"}
        from alerting.notifier import queue_alerts
        await queue_alerts("example.com", SAMPLE_RESULTS, config)  # SAMPLE = HIGH, min = CRITICAL
        from core.database import db_session, Alert
        with db_session() as db:
            count = db.query(Alert).count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_queue_alerts_persists_records(self):
        from alerting.notifier import queue_alerts
        await queue_alerts("example.com", SAMPLE_RESULTS, BASE_CONFIG)
        from core.database import db_session, Alert
        with db_session() as db:
            alerts = db.query(Alert).filter_by(target="example.com").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "HIGH"
        assert alerts[0].sent is False

    @pytest.mark.asyncio
    async def test_queue_alerts_critical_persisted(self):
        from alerting.notifier import queue_alerts
        await queue_alerts("example.com", CRITICAL_RESULTS, BASE_CONFIG)
        from core.database import db_session, Alert
        with db_session() as db:
            alerts = db.query(Alert).filter_by(target="example.com").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "CRITICAL"


class TestWebhookValidation:
    def test_valid_slack_url_accepted(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("https://hooks.slack.com/services/abc/def/ghi") is True

    def test_valid_discord_url_accepted(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("https://discord.com/api/webhooks/123/abc") is True

    def test_http_url_rejected(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("http://hooks.slack.com/services/abc") is False

    def test_internal_ip_rejected(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("https://192.168.1.1/webhook") is False

    def test_localhost_rejected(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("https://localhost/webhook") is False

    def test_empty_url_rejected(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("") is False

    def test_unknown_host_rejected(self):
        from alerting.notifier import _validate_webhook_url
        assert _validate_webhook_url("https://evil.example.com/webhook") is False


class TestDispatchAlerts:
    @pytest.mark.asyncio
    async def test_dispatch_skips_invalid_slack_url(self):
        config = {
            "alerting": {
                "slack": {"enabled": True, "webhook_url": "http://internal/webhook"},
                "discord": {"enabled": False},
                "smtp": {"enabled": False},
            }
        }
        from alerting.notifier import dispatch_alerts
        # Should not raise, just log a warning and skip
        await dispatch_alerts(SAMPLE_RESULTS, "example.com", config)

    @pytest.mark.asyncio
    async def test_dispatch_calls_slack_with_valid_url(self):
        config = {
            "alerting": {
                "slack": {
                    "enabled": True,
                    "webhook_url": "https://hooks.slack.com/services/T/B/token",
                },
                "discord": {"enabled": False},
                "smtp": {"enabled": False},
            }
        }
        from alerting.notifier import dispatch_alerts
        with patch("alerting.notifier._send_slack", new=AsyncMock()) as mock_slack:
            await dispatch_alerts(SAMPLE_RESULTS, "example.com", config)
            mock_slack.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_calls_discord_with_valid_url(self):
        config = {
            "alerting": {
                "slack": {"enabled": False},
                "discord": {
                    "enabled": True,
                    "webhook_url": "https://discord.com/api/webhooks/123/token",
                },
                "smtp": {"enabled": False},
            }
        }
        from alerting.notifier import dispatch_alerts
        with patch("alerting.notifier._send_discord", new=AsyncMock()) as mock_discord:
            await dispatch_alerts(CRITICAL_RESULTS, "example.com", config)
            mock_discord.assert_called_once()


class TestEmailGeneration:
    def test_email_escapes_html_in_value(self):
        """Ensure HTML injection in credential values is escaped in email body."""
        from alerting.notifier import _send_email_sync

        malicious_results = [
            {
                "source_feed": "HIBP",
                "exposure_type": "test",
                "value": "<script>alert(1)</script>",
                "severity": "HIGH",
                "breach_name": "<img src=x onerror=alert(1)>",
            }
        ]

        smtp_cfg = {
            "host": "localhost",
            "port": 25,
            "user": "",
            "password": "",
            "from_email": "from@example.com",
            "to_email": "to@example.com",
            "use_tls": False,
        }

        import smtplib
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = lambda s: mock_server
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            mock_server.sendmail = MagicMock()
            _send_email_sync(malicious_results, "example.com", smtp_cfg)
            call_args = mock_server.sendmail.call_args
            if call_args:
                email_body = call_args[0][2]
                assert "<script>" not in email_body
                assert "alert(1)" not in email_body or "&lt;script&gt;" in email_body
