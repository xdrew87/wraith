import pytest
from unittest.mock import patch, AsyncMock, MagicMock


BASE_CONFIG = {
    "feeds": {
        "hibp": {"enabled": True, "api_key": "test-key", "base_url": "https://haveibeenpwned.com/api/v3"},
        "dehashed": {"enabled": False, "email": "", "api_key": ""},
        "intelx": {"enabled": False, "api_key": ""},
        "pastebin": {"enabled": False},
        "github": {"enabled": False, "token": ""},
    },
    "monitor": {"max_concurrent_feeds": 5},
    "database": {"sqlite_path": ":memory:"},
}


class TestAggregator:
    def test_detect_target_type_email(self):
        from core.aggregator import detect_target_type
        assert detect_target_type("user@example.com") == "email"

    def test_detect_target_type_domain(self):
        from core.aggregator import detect_target_type
        assert detect_target_type("example.com") == "domain"

    def test_make_result_hash_is_deterministic(self):
        from feeds.base import BaseFeed
        feed = BaseFeed.__new__(BaseFeed)
        r1 = feed.make_result("example.com", "HIBP", "email_breach", "test@example.com", "HIGH")
        r2 = feed.make_result("example.com", "HIBP", "email_breach", "test@example.com", "HIGH")
        assert r1["hash"] == r2["hash"]

    def test_make_result_different_values_different_hash(self):
        from feeds.base import BaseFeed
        feed = BaseFeed.__new__(BaseFeed)
        r1 = feed.make_result("example.com", "HIBP", "email_breach", "a@example.com", "HIGH")
        r2 = feed.make_result("example.com", "HIBP", "email_breach", "b@example.com", "HIGH")
        assert r1["hash"] != r2["hash"]

    @pytest.mark.asyncio
    async def test_run_feed_skips_unsupported_type(self):
        from core.aggregator import run_feed
        from feeds.hibp import HIBPFeed

        # HIBP doesn't support 'hash' type
        results = await run_feed("hibp", HIBPFeed, BASE_CONFIG, "abc123", "hash")
        assert results == []

    @pytest.mark.asyncio
    async def test_aggregate_returns_combined_results(self):
        from core.aggregator import aggregate
        from core.database import init_db

        init_db(BASE_CONFIG)

        mock_results = [
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
                "hash": "abc123unique",
            }
        ]

        with patch("core.aggregator.run_feed", new=AsyncMock(return_value=mock_results)):
            results = await aggregate("example.com", BASE_CONFIG, ["hibp"])

        assert len(results) > 0
