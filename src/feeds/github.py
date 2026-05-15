import logging
import re

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"), "api_key"),
    (re.compile(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"), "secret_key"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?"), "password"),
    (re.compile(r"(?i)(token|access[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?"), "token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"), "private_key"),
]


class GitHubFeed(BaseFeed):
    """GitHub code search — scans public repos for domain/email/credential pattern matches."""

    name = "GitHub"
    supported_types = ["domain", "email"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("github", {})
        self.token = feed_cfg.get("token", "")
        self.base_url = feed_cfg.get("base_url", "https://api.github.com")

    def _headers(self) -> dict:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "WRAITH-CredMonitor/1.0",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if not self.token:
            logger.warning("[GitHub] No token configured — rate limits will be very low")

        results = []

        # Search for domain/email mentions in code
        code_results = await self._code_search(target)
        for item in code_results:
            repo = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            # Check for credential patterns in the file
            file_content = await self._fetch_raw(item.get("url", ""))
            exposures = self._scan_for_secrets(file_content)

            if exposures:
                for exp_type, exp_value in exposures:
                    results.append(self.make_result(
                        target=target,
                        source_feed=self.name,
                        exposure_type=exp_type,
                        value=f"{repo}/{file_path}: {exp_value[:80]}",
                        severity="CRITICAL" if exp_type in ("github_token", "aws_access_key", "private_key") else "HIGH",
                        breach_name=repo,
                        description=f"Credential found in public repo: {html_url}",
                        raw={"repo": repo, "path": file_path, "url": html_url, "type": exp_type},
                    ))
            else:
                # Still record the domain/email mention even without extracted secret
                results.append(self.make_result(
                    target=target,
                    source_feed=self.name,
                    exposure_type="code_mention",
                    value=f"{repo}/{file_path}",
                    severity="LOW",
                    breach_name=repo,
                    description=f"Target mentioned in public repo: {html_url}",
                    raw={"repo": repo, "path": file_path, "url": html_url},
                ))

        return results

    async def _code_search(self, target: str) -> list[dict]:
        url = f"{self.base_url}/search/code"
        params = {"q": f'"{target}"', "per_page": 30}
        data = await self._get(url, headers=self._headers(), params=params)
        return data.get("items", [])

    async def _fetch_raw(self, api_url: str) -> str:
        if not api_url:
            return ""
        headers = self._headers()
        headers["Accept"] = "application/vnd.github.raw+json"
        data = await self._get(api_url, headers=headers)
        return data.get("_text", "")

    def _scan_for_secrets(self, content: str) -> list[tuple[str, str]]:
        found = []
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                val = match.group(0)
                found.append((label, val[:100]))
        return found
