"""Tests for modules/models.py — dataclass defaults and field independence."""

from modules.models import (
    WhoisResult, DNSResult, Subdomain, SubdomainResult,
    EmailResult, Technology, TechResult, OpenPort,
    PortScanResult, ShodanVuln, ShodanHostInfo, ShodanResult, ReconResult,
)


class TestDataclassDefaults:
    """Verify default values are correct for all dataclasses."""

    def test_whois_result_defaults(self):
        r = WhoisResult(domain="example.com")
        assert r.registrar is None
        assert r.name_servers == []
        assert r.status == []
        assert r.error is None

    def test_dns_result_defaults(self):
        r = DNSResult(domain="example.com")
        assert r.a_records == []
        assert r.mx_records == []
        assert r.ns_records == []
        assert r.txt_records == []
        assert r.cname_records == []
        assert r.error is None

    def test_subdomain_result_defaults(self):
        r = SubdomainResult(domain="example.com")
        assert r.subdomains == []
        assert r.total_checked == 0

    def test_email_result_defaults(self):
        r = EmailResult(domain="example.com")
        assert r.emails == []
        assert r.source == ""

    def test_tech_result_defaults(self):
        r = TechResult(domain="example.com", url="https://example.com")
        assert r.technologies == []
        assert r.server is None
        assert r.powered_by is None

    def test_port_scan_result_defaults(self):
        r = PortScanResult(target="127.0.0.1")
        assert r.open_ports == []
        assert r.scanned_range == "1-1024"

    def test_shodan_result_defaults(self):
        r = ShodanResult(domain="example.com")
        assert r.hosts == []
        assert r.error is None

    def test_recon_result_defaults(self):
        r = ReconResult(domain="example.com")
        assert r.whois is None
        assert r.dns is None
        assert r.subdomains is None
        assert r.emails is None
        assert r.tech is None
        assert r.port_scan is None
        assert r.shodan is None


class TestFieldIndependence:
    """Verify mutable default fields are independent between instances."""

    def test_dns_lists_independent(self):
        r1 = DNSResult(domain="a.com")
        r2 = DNSResult(domain="b.com")
        r1.a_records.append("1.2.3.4")
        assert r2.a_records == []

    def test_subdomain_lists_independent(self):
        r1 = SubdomainResult(domain="a.com")
        r2 = SubdomainResult(domain="b.com")
        r1.subdomains.append(Subdomain(name="www", ip="1.2.3.4"))
        assert r2.subdomains == []

    def test_shodan_hosts_independent(self):
        r1 = ShodanResult(domain="a.com")
        r2 = ShodanResult(domain="b.com")
        r1.hosts.append(ShodanHostInfo(ip="1.2.3.4"))
        assert r2.hosts == []


class TestDataclassValues:
    """Test dataclasses with actual values."""

    def test_technology_with_version(self):
        t = Technology(name="React", category="JS Framework", version="18.2")
        assert t.name == "React"
        assert t.version == "18.2"

    def test_open_port_with_banner(self):
        p = OpenPort(port=22, banner="SSH-2.0-OpenSSH_8.9")
        assert p.port == 22
        assert "SSH" in p.banner

    def test_shodan_vuln(self):
        v = ShodanVuln(cve_id="CVE-2024-1234", cvss=9.8, summary="Critical RCE")
        assert v.cve_id == "CVE-2024-1234"
        assert v.cvss == 9.8
