import logging

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)


class HIBPFeed(BaseFeed):
    """HaveIBeenPwned v3 API — breach lookup by email or domain."""

    name = "HIBP"
    supported_types = ["email", "domain"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("hibp", {})
        self.api_key = feed_cfg.get("api_key", "")
        self.base_url = feed_cfg.get("base_url", "https://haveibeenpwned.com/api/v3")

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if not self.api_key:
            logger.warning("[HIBP] No API key configured — skipping")
            return []

        if target_type == "email":
            return await self._lookup_email(target)
        elif target_type == "domain":
            return await self._lookup_domain(target)
        return []

    async def _lookup_email(self, email: str) -> list[dict]:
        url = f"{self.base_url}/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "WRAITH-CredMonitor/1.0",
        }
        params = {"truncateResponse": "false"}
        data = await self._get(url, headers=headers, params=params)

        results = []
        if isinstance(data, list):
            for breach in data:
                severity = self._classify_severity(breach.get("DataClasses", []))
                results.append(self.make_result(
                    target=email,
                    source_feed=self.name,
                    exposure_type="email_breach",
                    value=email,
                    severity=severity,
                    breach_name=breach.get("Name"),
                    breach_date=breach.get("BreachDate"),
                    description=f"Exposed in {breach.get('Name')} breach. "
                                f"Data types: {', '.join(breach.get('DataClasses', []))}",
                    raw=breach,
                ))
        return results

    async def _lookup_domain(self, domain: str) -> list[dict]:
        """HIBP domain search — requires enterprise key."""
        url = f"{self.base_url}/breacheddomain/{domain}"
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "WRAITH-CredMonitor/1.0",
        }
        data = await self._get(url, headers=headers)

        results = []
        if isinstance(data, dict):
            for email, breaches in data.items():
                for breach_name in breaches:
                    results.append(self.make_result(
                        target=domain,
                        source_feed=self.name,
                        exposure_type="domain_breach",
                        value=email,
                        severity="HIGH",
                        breach_name=breach_name,
                        description=f"{email} exposed in {breach_name}",
                        raw={"email": email, "breach": breach_name},
                    ))
        return results

    def _classify_severity(self, data_classes: list[str]) -> str:
        critical_types = {"passwords", "password hints", "credit cards", "bank account numbers", "private keys"}
        high_types = {"email addresses", "usernames", "phone numbers", "physical addresses", "social security numbers"}

        classes_lower = {c.lower() for c in data_classes}
        if classes_lower & critical_types:
            return "CRITICAL"
        if classes_lower & high_types:
            return "HIGH"
        return "MEDIUM"
