import logging

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


class HudsonRockFeed(BaseFeed):
    """HudsonRock Cavalier — free infostealer credential intelligence (no API key required).

    Queries HudsonRock's public Cavalier API for credentials harvested by
    infostealer malware that targeted a given domain or email address.
    """

    name = "HudsonRock"
    supported_types = ["domain", "email"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("hudsonrock", {})
        self.base_url = feed_cfg.get("base_url", BASE_URL)

    def _headers(self) -> dict:
        return {"User-Agent": "WRAITH-CredMonitor/1.0", "Accept": "application/json"}

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if target_type == "domain":
            return await self._search_domain(target)
        if target_type == "email":
            return await self._search_email(target)
        return []

    async def _search_domain(self, domain: str) -> list[dict]:
        url = f"{self.base_url}/search-by-domain"
        data = await self._get(url, headers=self._headers(), params={"domain": domain})
        if not isinstance(data, dict):
            return []

        results = []
        total = data.get("stealers", 0)
        if not total:
            return []

        for category in ("employees", "users", "third_parties"):
            for entry in data.get(category, []) or []:
                username = entry.get("username") or entry.get("email") or ""
                url_val = entry.get("url") or entry.get("domain") or domain
                computer = entry.get("computer_name", "")
                os_name = entry.get("operating_system", "")
                date_added = entry.get("dateadded", "")

                if not username:
                    continue

                results.append(
                    self.make_result(
                        target=domain,
                        source_feed=self.name,
                        exposure_type="infostealer_credential",
                        value=username,
                        severity="CRITICAL",
                        breach_name=f"infostealer:{computer or 'unknown'}",
                        breach_date=date_added[:10] if date_added else None,
                        description=(
                            f"Infostealer credential ({category}) for {url_val}"
                            + (f" — OS: {os_name}" if os_name else "")
                        ),
                        raw={
                            "category": category,
                            "username": username,
                            "url": url_val,
                            "computer": computer,
                            "os": os_name,
                            "date": date_added,
                        },
                    )
                )

        return results

    async def _search_email(self, email: str) -> list[dict]:
        url = f"{self.base_url}/search-by-email"
        data = await self._get(url, headers=self._headers(), params={"email": email})
        if not isinstance(data, dict):
            return []

        stealers = data.get("stealers", 0)
        if not stealers:
            return []

        results = []
        for entry in data.get("credentials", []) or []:
            url_val = entry.get("url") or ""
            password = entry.get("password") or ""
            computer = entry.get("computer_name", "")
            date_added = entry.get("dateadded", "")

            results.append(
                self.make_result(
                    target=email,
                    source_feed=self.name,
                    exposure_type="infostealer_credential",
                    value=f"{email}:{password[:4]}***" if password else email,
                    severity="CRITICAL",
                    breach_name=f"infostealer:{computer or 'unknown'}",
                    breach_date=date_added[:10] if date_added else None,
                    description=f"Infostealer credential found for {url_val or email}",
                    raw={
                        "email": email,
                        "url": url_val,
                        "computer": computer,
                        "date": date_added,
                    },
                )
            )

        return results
