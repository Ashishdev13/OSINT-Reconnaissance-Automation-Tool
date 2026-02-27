"""
WHOIS Lookup Module
Retrieves domain registration information using python-whois.

Usage (standalone):
    python -m modules.whois_lookup example.com
"""

import time
import sys
import whois
from datetime import datetime
from .models import WhoisResult
import config


class WhoisLookup:
    def run(self, domain: str) -> WhoisResult:
        result = WhoisResult(domain=domain)
        try:
            time.sleep(config.RATE_LIMIT_API)
            w = whois.whois(domain)

            def _str(val) -> str | None:
                if val is None:
                    return None
                if isinstance(val, list):
                    val = val[0]
                if isinstance(val, datetime):
                    return val.strftime("%Y-%m-%d %H:%M:%S UTC")
                return str(val)

            def _list(val) -> list[str]:
                if val is None:
                    return []
                if isinstance(val, list):
                    return [str(v).lower() for v in val]
                return [str(val).lower()]

            result.registrar = _str(w.registrar)
            result.creation_date = _str(w.creation_date)
            result.expiration_date = _str(w.expiration_date)
            result.updated_date = _str(w.updated_date)
            result.name_servers = _list(w.name_servers)
            result.registrant_org = _str(w.org)
            result.registrant_country = _str(w.country)
            result.registrant_email = _str(w.emails)
            result.status = _list(w.status)
            result.raw = str(w)
        except Exception as e:
            result.error = str(e)
        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = WhoisLookup().run(domain)
    print(f"Registrar:   {res.registrar}")
    print(f"Created:     {res.creation_date}")
    print(f"Expires:     {res.expiration_date}")
    print(f"Name Servers:{res.name_servers}")
    print(f"Org:         {res.registrant_org}")
    if res.error:
        print(f"Error: {res.error}")
