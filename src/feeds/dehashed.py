import base64
import logging

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)


class DeHashedFeed(BaseFeed):
    """DeHashed API v1 — credential search by domain, email, username, or password hash."""

    name = "DeHashed"
    supported_types = ["email", "domain"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("dehashed", {})
        self.email = feed_cfg.get("email", "")
        self.api_key = feed_cfg.get("api_key", "")
        self.base_url = feed_cfg.get("base_url", "https://api.dehashed.com")

    def _auth_header(self) -> dict:
        token = base64.b64encode(f"{self.email}:{self.api_key}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if not self.email or not self.api_key:
            logger.warning("[DeHashed] No credentials configured — skipping")
            return []

        if target_type == "domain":
            query = f"domain:{target}"
        elif target_type == "email":
            query = f"email:{target}"
        else:
            return []

        return await self._search(target, query)

    async def _search(self, target: str, query: str) -> list[dict]:
        url = f"{self.base_url}/search"
        params = {"query": query, "size": 100}
        data = await self._get(url, headers=self._auth_header(), params=params)

        results = []
        entries = data.get("entries") or []
        for entry in entries:
            email = entry.get("email", "")
            password = entry.get("password", "")
            hashed_password = entry.get("hashed_password", "")
            database_name = entry.get("database_name", "")

            if password:
                results.append(self.make_result(
                    target=target,
                    source_feed=self.name,
                    exposure_type="plaintext_password",
                    value=f"{email}:{password}" if email else password,
                    severity="CRITICAL",
                    breach_name=database_name,
                    description=f"Plaintext password found in {database_name}",
                    raw=entry,
                ))
            elif hashed_password:
                results.append(self.make_result(
                    target=target,
                    source_feed=self.name,
                    exposure_type="hashed_password",
                    value=f"{email}:{hashed_password}" if email else hashed_password,
                    severity="HIGH",
                    breach_name=database_name,
                    description=f"Hashed password found in {database_name}",
                    raw=entry,
                ))
            elif email:
                results.append(self.make_result(
                    target=target,
                    source_feed=self.name,
                    exposure_type="email_exposure",
                    value=email,
                    severity="MEDIUM",
                    breach_name=database_name,
                    description=f"Email found in {database_name}",
                    raw=entry,
                ))

        return results
