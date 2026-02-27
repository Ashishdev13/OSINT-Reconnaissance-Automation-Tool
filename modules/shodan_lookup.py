"""
Shodan API Module
Looks up known vulnerabilities and host info for discovered IPs.

Usage (standalone):
    python -m modules.shodan_lookup example.com
"""

import sys
import time
import socket
import shodan
from .models import ShodanResult, ShodanHostInfo, ShodanVuln
import config


class ShodanLookup:
    def _lookup_ip(self, api: shodan.Shodan, ip: str) -> ShodanHostInfo:
        info = ShodanHostInfo(ip=ip)
        try:
            time.sleep(config.RATE_LIMIT_API)
            host = api.host(ip)
            info.org = host.get("org")
            info.os = host.get("os")
            info.country = host.get("country_name")
            info.ports = host.get("ports", [])
            info.hostnames = host.get("hostnames", [])

            # Parse vulnerabilities
            for cve_id, cve_data in host.get("vulns", {}).items():
                info.vulns.append(ShodanVuln(
                    cve_id=cve_id,
                    cvss=cve_data.get("cvss"),
                    summary=cve_data.get("summary", "")[:200],
                ))
            info.vulns.sort(key=lambda v: v.cvss or 0, reverse=True)
        except shodan.APIError as e:
            info.error = str(e)
        except Exception as e:
            info.error = str(e)
        return info

    def run(self, domain: str, ips: list[str] | None = None) -> ShodanResult:
        result = ShodanResult(domain=domain)

        if not config.SHODAN_API_KEY:
            result.error = "SHODAN_API_KEY not set"
            return result

        # Resolve domain IPs if none provided
        if not ips:
            try:
                addr_infos = socket.getaddrinfo(domain, None)
                ips = list({info[4][0] for info in addr_infos})
            except Exception as e:
                result.error = f"Cannot resolve IPs for {domain}: {e}"
                return result

        try:
            api = shodan.Shodan(config.SHODAN_API_KEY)
            for ip in ips:
                host_info = self._lookup_ip(api, ip)
                result.hosts.append(host_info)
        except Exception as e:
            result.error = str(e)

        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = ShodanLookup().run(domain)
    for host in res.hosts:
        print(f"\nIP: {host.ip}")
        print(f"  Org:     {host.org}")
        print(f"  OS:      {host.os}")
        print(f"  Country: {host.country}")
        print(f"  Ports:   {host.ports}")
        print(f"  Vulns:   {len(host.vulns)}")
        for v in host.vulns[:5]:
            print(f"    {v.cve_id} (CVSS {v.cvss}): {v.summary[:80]}")
    if res.error:
        print(f"Error: {res.error}")
