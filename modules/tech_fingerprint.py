"""
Technology Fingerprinting Module
Identifies technologies via HTTP headers and Wappalyzer-style pattern matching.
Falls back to BuiltWith API if BUILTWITH_API_KEY is set.

Usage (standalone):
    python -m modules.tech_fingerprint example.com
"""

import sys
import re
import time
import json
import requests
from .models import TechResult, Technology
import config

# Inline Wappalyzer-style pattern matching (header + body patterns)
# Format: { "Tech Name": {"category": "...", "headers": {...}, "html": [...]} }
TECH_PATTERNS: dict = {
    "WordPress": {
        "category": "CMS",
        "headers": {"X-Powered-By": r"WordPress"},
        "html": [r"/wp-content/", r"/wp-includes/", r'name="generator"[^>]*WordPress'],
    },
    "Drupal": {
        "category": "CMS",
        "headers": {"X-Generator": r"Drupal"},
        "html": [r"/sites/default/files/", r'Drupal\.settings'],
    },
    "Joomla": {
        "category": "CMS",
        "html": [r"/components/com_", r"joomla"],
    },
    "React": {
        "category": "JavaScript Framework",
        "html": [r"react(?:\.min)?\.js", r'data-reactroot', r'__reactFiber'],
    },
    "Vue.js": {
        "category": "JavaScript Framework",
        "html": [r"vue(?:\.min)?\.js", r'data-v-[a-f0-9]+'],
    },
    "Angular": {
        "category": "JavaScript Framework",
        "html": [r"angular(?:\.min)?\.js", r'ng-version='],
    },
    "Next.js": {
        "category": "JavaScript Framework",
        "html": [r"/_next/static/", r'__NEXT_DATA__'],
    },
    "jQuery": {
        "category": "JavaScript Library",
        "html": [r"jquery(?:\.min)?\.js"],
    },
    "Bootstrap": {
        "category": "UI Framework",
        "html": [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"],
    },
    "Tailwind CSS": {
        "category": "UI Framework",
        "html": [r"tailwind(?:css)?(?:\.min)?\.css", r'class="[^"]*(?:flex|grid|text-|bg-)'],
    },
    "Nginx": {
        "category": "Web Server",
        "headers": {"Server": r"nginx"},
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"Server": r"Apache"},
    },
    "Cloudflare": {
        "category": "CDN",
        "headers": {"Server": r"cloudflare", "CF-Ray": r".+"},
    },
    "PHP": {
        "category": "Programming Language",
        "headers": {"X-Powered-By": r"PHP"},
        "html": [r'\.php(?:\?|")'],
    },
    "Python/Django": {
        "category": "Framework",
        "headers": {"X-Framework": r"Django"},
        "html": [r"csrfmiddlewaretoken"],
    },
    "ASP.NET": {
        "category": "Framework",
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
    },
    "Google Analytics": {
        "category": "Analytics",
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+"],
    },
    "Google Tag Manager": {
        "category": "Tag Manager",
        "html": [r"googletagmanager\.com/gtm\.js"],
    },
    "Shopify": {
        "category": "E-commerce",
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    "WooCommerce": {
        "category": "E-commerce",
        "html": [r"woocommerce", r"/wc-api/"],
    },
    "Stripe": {
        "category": "Payment",
        "html": [r"js\.stripe\.com"],
    },
    "reCAPTCHA": {
        "category": "Security",
        "html": [r"google\.com/recaptcha"],
    },
    "Varnish": {
        "category": "Cache",
        "headers": {"Via": r"varnish", "X-Varnish": r".+"},
    },
    "Node.js": {
        "category": "Runtime",
        "headers": {"X-Powered-By": r"Express"},
    },
}

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class TechFingerprint:
    def _builtwith(self, domain: str) -> list[Technology]:
        if not config.BUILTWITH_API_KEY:
            return []
        try:
            time.sleep(config.RATE_LIMIT_API)
            url = f"https://api.builtwith.com/free1/api.json"
            params = {"KEY": config.BUILTWITH_API_KEY, "LOOKUP": domain}
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            techs = []
            for group in data.get("Results", [{}])[0].get("Result", {}).get("Paths", []):
                for tech in group.get("Technologies", []):
                    techs.append(Technology(
                        name=tech.get("Name", "Unknown"),
                        category=tech.get("Categories", [""])[0] if tech.get("Categories") else None,
                    ))
            return techs
        except Exception:
            return []

    def _pattern_match(self, response: requests.Response) -> list[Technology]:
        found: list[Technology] = []
        body = response.text
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        for tech_name, patterns in TECH_PATTERNS.items():
            matched = False
            # Check headers
            for header_key, pattern in patterns.get("headers", {}).items():
                val = resp_headers.get(header_key.lower(), "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    matched = True
                    break
            # Check HTML body
            if not matched:
                for pattern in patterns.get("html", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        matched = True
                        break
            if matched:
                found.append(Technology(
                    name=tech_name,
                    category=patterns.get("category"),
                ))
        return found

    def run(self, domain: str) -> TechResult:
        url = f"https://{domain}"
        result = TechResult(domain=domain, url=url)
        try:
            time.sleep(config.RATE_LIMIT_HTTP)
            resp = requests.get(url, headers=_HEADERS, timeout=10, allow_redirects=True)
            result.url = resp.url

            result.server = resp.headers.get("Server")
            result.powered_by = resp.headers.get("X-Powered-By")

            # Pattern matching
            result.technologies = self._pattern_match(resp)

            # BuiltWith API (if key available)
            bw_techs = self._builtwith(domain)
            existing_names = {t.name for t in result.technologies}
            for t in bw_techs:
                if t.name not in existing_names:
                    result.technologies.append(t)

        except requests.exceptions.SSLError:
            try:
                url = f"http://{domain}"
                time.sleep(config.RATE_LIMIT_HTTP)
                resp = requests.get(url, headers=_HEADERS, timeout=10, allow_redirects=True)
                result.url = resp.url
                result.server = resp.headers.get("Server")
                result.powered_by = resp.headers.get("X-Powered-By")
                result.technologies = self._pattern_match(resp)
            except Exception as e:
                result.error = str(e)
        except Exception as e:
            result.error = str(e)
        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = TechFingerprint().run(domain)
    print(f"URL:        {res.url}")
    print(f"Server:     {res.server}")
    print(f"Powered by: {res.powered_by}")
    print(f"Technologies ({len(res.technologies)}):")
    for t in res.technologies:
        print(f"  [{t.category}] {t.name}")
    if res.error:
        print(f"Error: {res.error}")
