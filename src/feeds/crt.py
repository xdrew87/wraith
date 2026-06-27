import logging
import re

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class CrtShFeed(BaseFeed):
    """crt.sh Certificate Transparency feed — free, no API key required.

    Queries crt.sh for TLS certificates issued for a domain, extracting
    email addresses from Subject Alternative Names (SANs) and revealing
    subdomains that may be attack surface.
    """

    name = "crt.sh"
    supported_types = ["domain"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("crtsh", {})
        self.base_url = feed_cfg.get("base_url", "https://crt.sh")

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if target_type != "domain":
            return []

        url = f"{self.base_url}/"
        params = {"q": f"%.{target}", "output": "json"}
        data = await self._get(url, params=params, headers={"Accept": "application/json"})

        if isinstance(data, dict) and "_text" in data:
            # crt.sh returns raw JSON text sometimes
            import json

            try:
                records = json.loads(data["_text"])
            except (json.JSONDecodeError, TypeError):
                return []
        elif isinstance(data, list):
            records = data
        else:
            return []

        return self._parse_records(target, records)

    def _parse_records(self, domain: str, records: list) -> list[dict]:
        seen_emails: set[str] = set()
        seen_subdomains: set[str] = set()
        results = []

        for record in records:
            name_value: str = record.get("name_value") or ""
            not_before: str = (record.get("not_before") or "")[:10] or None
            issuer: str = record.get("issuer_name") or ""
            cert_id = record.get("id")
            cert_url = f"https://crt.sh/?id={cert_id}" if cert_id else ""

            for line in name_value.splitlines():
                line = line.strip().lower()
                if not line or line == domain.lower():
                    continue

                # Email SANs in certificates (format: "email:user@example.com" or raw email)
                emails = EMAIL_RE.findall(line)
                for email in emails:
                    if domain.lower() in email and email not in seen_emails:
                        seen_emails.add(email)
                        results.append(
                            self.make_result(
                                target=domain,
                                source_feed=self.name,
                                exposure_type="cert_email_san",
                                value=email,
                                severity="LOW",
                                breach_name=f"certificate:{issuer[:40]}",
                                breach_date=not_before,
                                description=f"Email SAN in TLS certificate: {cert_url}",
                                raw={"email": email, "issuer": issuer, "cert_url": cert_url},
                            )
                        )

                # Subdomains — only record each unique subdomain once
                if line.endswith(f".{domain.lower()}") and line not in seen_subdomains:
                    seen_subdomains.add(line)
                    results.append(
                        self.make_result(
                            target=domain,
                            source_feed=self.name,
                            exposure_type="cert_subdomain",
                            value=line,
                            severity="INFO",
                            breach_name=f"certificate:{issuer[:40]}",
                            breach_date=not_before,
                            description=f"Subdomain observed in TLS certificate: {cert_url}",
                            raw={"subdomain": line, "issuer": issuer, "cert_url": cert_url},
                        )
                    )

        logger.debug(
            "[crt.sh] %d email SANs, %d subdomains found for %s",
            len(seen_emails),
            len(seen_subdomains),
            domain,
        )
        return results
