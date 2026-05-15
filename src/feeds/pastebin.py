import logging
import re

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class PastebinFeed(BaseFeed):
    """Pastebin scraper — scans recent public pastes for domain/email pattern matches.

    Note: Pastebin's scraping API requires a PRO account.
    """

    name = "Pastebin"
    supported_types = ["domain", "email"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("pastebin", {})
        self.scrape_url = feed_cfg.get("scrape_url", "https://scrape.pastebin.com/api_scraping.php")
        self.fetch_url = feed_cfg.get("fetch_url", "https://scrape.pastebin.com/api_scrape_item.php")
        self.limit = feed_cfg.get("limit", 100)

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        pastes = await self._get_recent_pastes()
        if not pastes:
            logger.debug("[Pastebin] No pastes returned (PRO account required for scrape API)")
            return []

        results = []
        for paste in pastes:
            paste_key = paste.get("key", "")
            paste_title = paste.get("title", "")
            content = await self._fetch_paste(paste_key)
            if not content:
                continue

            hits = self._scan_content(content, target, target_type)
            for hit_value in hits:
                exposure_type = "paste_email" if "@" in hit_value else "paste_domain_hit"
                results.append(self.make_result(
                    target=target,
                    source_feed=self.name,
                    exposure_type=exposure_type,
                    value=hit_value,
                    severity="HIGH",
                    breach_name=f"pastebin:{paste_key}",
                    description=f"Match found in Pastebin paste '{paste_title}' "
                                f"(https://pastebin.com/{paste_key})",
                    raw={"key": paste_key, "title": paste_title, "hit": hit_value},
                ))

        return results

    async def _get_recent_pastes(self) -> list[dict]:
        params = {"limit": self.limit}
        data = await self._get(self.scrape_url, params=params)
        if isinstance(data, list):
            return data
        text = data.get("_text", "")
        if "DOES NOT HAVE ACCESS" in text or "NOT ALLOWED" in text:
            logger.warning("[Pastebin] Scrape API requires PRO account")
            return []
        return []

    async def _fetch_paste(self, paste_key: str) -> str:
        params = {"i": paste_key}
        data = await self._get(self.fetch_url, params=params)
        return data.get("_text", "")

    def _scan_content(self, content: str, target: str, target_type: str) -> list[str]:
        hits = set()
        content_lower = content.lower()

        if target_type == "domain":
            if target.lower() in content_lower:
                # Extract matching emails for this domain
                for email in EMAIL_RE.findall(content):
                    if target.lower() in email.lower():
                        hits.add(email)
                if not hits:
                    hits.add(target)
        elif target_type == "email":
            if target.lower() in content_lower:
                hits.add(target)

        return list(hits)
