import pytest
from unittest.mock import AsyncMock, MagicMock, patch


BASE_CONFIG = {
    "feeds": {
        "hibp": {"enabled": True, "api_key": "test-key", "base_url": "https://haveibeenpwned.com/api/v3"},
        "dehashed": {"enabled": True, "email": "test@example.com", "api_key": "test-key", "base_url": "https://api.dehashed.com"},
        "intelx": {"enabled": True, "api_key": "test-key", "base_url": "https://2.intelx.io"},
        "pastebin": {"enabled": True, "scrape_url": "https://scrape.pastebin.com/api_scraping.php", "fetch_url": "https://scrape.pastebin.com/api_scrape_item.php", "limit": 10},
        "github": {"enabled": True, "token": "test-token", "base_url": "https://api.github.com"},
    },
    "monitor": {"max_concurrent_feeds": 5},
}


class TestHIBPFeed:
    @pytest.mark.asyncio
    async def test_lookup_email_returns_results(self):
        from feeds.hibp import HIBPFeed
        feed = HIBPFeed(BASE_CONFIG)

        breach_data = [
            {
                "Name": "TestBreach",
                "BreachDate": "2023-01-01",
                "DataClasses": ["Passwords", "Email addresses"],
            }
        ]

        with patch.object(feed, "_get", new=AsyncMock(return_value=breach_data)):
            results = await feed.lookup("user@example.com", "email")

        assert len(results) == 1
        assert results[0]["source_feed"] == "HIBP"
        assert results[0]["severity"] == "CRITICAL"
        assert results[0]["breach_name"] == "TestBreach"

    @pytest.mark.asyncio
    async def test_lookup_skips_without_api_key(self):
        from feeds.hibp import HIBPFeed
        config = {"feeds": {"hibp": {"enabled": True, "api_key": ""}}, "monitor": {"max_concurrent_feeds": 5}}
        feed = HIBPFeed(config)
        results = await feed.lookup("user@example.com", "email")
        assert results == []

    @pytest.mark.asyncio
    async def test_lookup_domain_returns_results(self):
        from feeds.hibp import HIBPFeed
        feed = HIBPFeed(BASE_CONFIG)

        domain_data = {"admin@example.com": ["BreachA"], "user@example.com": ["BreachB"]}

        with patch.object(feed, "_get", new=AsyncMock(return_value=domain_data)):
            results = await feed.lookup("example.com", "domain")

        assert len(results) == 2
        assert all(r["source_feed"] == "HIBP" for r in results)

    def test_severity_classification_critical(self):
        from feeds.hibp import HIBPFeed
        feed = HIBPFeed(BASE_CONFIG)
        assert feed._classify_severity(["Passwords"]) == "CRITICAL"

    def test_severity_classification_high(self):
        from feeds.hibp import HIBPFeed
        feed = HIBPFeed(BASE_CONFIG)
        assert feed._classify_severity(["Email addresses"]) == "HIGH"

    def test_severity_classification_medium(self):
        from feeds.hibp import HIBPFeed
        feed = HIBPFeed(BASE_CONFIG)
        assert feed._classify_severity(["Usernames"]) == "HIGH"


class TestDeHashedFeed:
    @pytest.mark.asyncio
    async def test_lookup_plaintext_password(self):
        from feeds.dehashed import DeHashedFeed
        feed = DeHashedFeed(BASE_CONFIG)

        mock_data = {
            "entries": [
                {"email": "admin@example.com", "password": "secret123", "database_name": "TestDB"}
            ]
        }

        with patch.object(feed, "_get", new=AsyncMock(return_value=mock_data)):
            results = await feed.lookup("example.com", "domain")

        assert len(results) == 1
        assert results[0]["severity"] == "CRITICAL"
        assert results[0]["exposure_type"] == "plaintext_password"

    @pytest.mark.asyncio
    async def test_lookup_skips_without_credentials(self):
        from feeds.dehashed import DeHashedFeed
        config = {"feeds": {"dehashed": {"email": "", "api_key": ""}}, "monitor": {"max_concurrent_feeds": 5}}
        feed = DeHashedFeed(config)
        results = await feed.lookup("example.com", "domain")
        assert results == []

    @pytest.mark.asyncio
    async def test_lookup_hashed_password(self):
        from feeds.dehashed import DeHashedFeed
        feed = DeHashedFeed(BASE_CONFIG)

        mock_data = {
            "entries": [
                {"email": "user@example.com", "hashed_password": "abc123hash", "database_name": "TestDB"}
            ]
        }

        with patch.object(feed, "_get", new=AsyncMock(return_value=mock_data)):
            results = await feed.lookup("example.com", "domain")

        assert results[0]["severity"] == "HIGH"
        assert results[0]["exposure_type"] == "hashed_password"


class TestGitHubFeed:
    @pytest.mark.asyncio
    async def test_detects_github_token(self):
        from feeds.github import GitHubFeed
        feed = GitHubFeed(BASE_CONFIG)
        content = "const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12';"
        secrets = feed._scan_for_secrets(content)
        assert any(label == "github_token" for label, _ in secrets)

    @pytest.mark.asyncio
    async def test_detects_aws_key(self):
        from feeds.github import GitHubFeed
        feed = GitHubFeed(BASE_CONFIG)
        content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        secrets = feed._scan_for_secrets(content)
        assert any(label == "aws_access_key" for label, _ in secrets)

    @pytest.mark.asyncio
    async def test_lookup_with_no_secrets_returns_mention(self):
        from feeds.github import GitHubFeed
        feed = GitHubFeed(BASE_CONFIG)

        mock_items = [{"repository": {"full_name": "user/repo"}, "path": "config.txt", "html_url": "https://github.com/user/repo/blob/main/config.txt", "url": "https://api.github.com/repos/user/repo/contents/config.txt"}]

        with patch.object(feed, "_code_search", new=AsyncMock(return_value=mock_items)):
            with patch.object(feed, "_fetch_raw", new=AsyncMock(return_value="example.com mentioned here")):
                results = await feed.lookup("example.com", "domain")

        assert len(results) == 1
        assert results[0]["exposure_type"] == "code_mention"
        assert results[0]["severity"] == "LOW"
