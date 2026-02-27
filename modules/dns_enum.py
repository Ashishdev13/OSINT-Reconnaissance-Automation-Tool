"""
DNS Enumeration Module
Queries A, MX, NS, TXT, and CNAME records using dnspython.

Usage (standalone):
    python -m modules.dns_enum example.com
"""

import sys
import time
import dns.resolver
from .models import DNSResult
import config


class DNSEnum:
    def _query(self, domain: str, record_type: str) -> list[str]:
        try:
            time.sleep(config.RATE_LIMIT_DNS)
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            return [r.to_text().rstrip(".") for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def run(self, domain: str) -> DNSResult:
        result = DNSResult(domain=domain)
        try:
            result.a_records = self._query(domain, "A")
            result.mx_records = self._query(domain, "MX")
            result.ns_records = self._query(domain, "NS")
            result.txt_records = self._query(domain, "TXT")
            result.cname_records = self._query(domain, "CNAME")
        except Exception as e:
            result.error = str(e)
        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = DNSEnum().run(domain)
    print(f"A:     {res.a_records}")
    print(f"MX:    {res.mx_records}")
    print(f"NS:    {res.ns_records}")
    print(f"TXT:   {res.txt_records}")
    print(f"CNAME: {res.cname_records}")
    if res.error:
        print(f"Error: {res.error}")
