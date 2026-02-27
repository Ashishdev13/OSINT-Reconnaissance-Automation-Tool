"""
Email Harvesting Module
Collects email addresses via Hunter.io API and Google search scraping.

Usage (standalone):
    python -m modules.email_harvest example.com
"""

import sys
import re
import time
import requests
from bs4 import BeautifulSoup
from .models import EmailResult
import config

# Common headers to mimic a browser
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class EmailHarvest:
    def _hunter_io(self, domain: str) -> list[str]:
        if not config.HUNTER_API_KEY:
            return []
        try:
            time.sleep(config.RATE_LIMIT_API)
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                "domain": domain,
                "api_key": config.HUNTER_API_KEY,
                "limit": 100,
            }
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            emails = data.get("data", {}).get("emails", [])
            return [e["value"] for e in emails if e.get("value")]
        except Exception:
            return []

    def _google_scrape(self, domain: str) -> list[str]:
        emails: set[str] = set()
        queries = [
            f'site:{domain} "@{domain}"',
            f'"@{domain}" email contact',
        ]
        for query in queries:
            try:
                time.sleep(config.RATE_LIMIT_HTTP)
                url = "https://www.google.com/search"
                params = {"q": query, "num": 30}
                resp = requests.get(url, headers=_HEADERS, params=params, timeout=10)
                if resp.status_code == 429:
                    break  # Rate limited by Google
                soup = BeautifulSoup(resp.text, "html.parser")
                text = soup.get_text()
                found = _EMAIL_RE.findall(text)
                for e in found:
                    if domain in e:
                        emails.add(e.lower())
            except Exception:
                continue
        return list(emails)

    def run(self, domain: str) -> EmailResult:
        result = EmailResult(domain=domain)
        all_emails: set[str] = set()
        sources: list[str] = []

        hunter_emails = self._hunter_io(domain)
        if hunter_emails:
            all_emails.update(hunter_emails)
            sources.append("Hunter.io")

        google_emails = self._google_scrape(domain)
        if google_emails:
            all_emails.update(google_emails)
            sources.append("Google")

        result.emails = sorted(all_emails)
        result.source = ", ".join(sources) if sources else "None"
        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = EmailHarvest().run(domain)
    print(f"Sources: {res.source}")
    print(f"Found {len(res.emails)} emails:")
    for e in res.emails:
        print(f"  {e}")
    if res.error:
        print(f"Error: {res.error}")
