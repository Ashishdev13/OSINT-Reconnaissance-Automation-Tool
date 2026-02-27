"""
Shared data models passed between OSINT modules.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WhoisResult:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    status: list[str] = field(default_factory=list)
    raw: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DNSResult:
    domain: str
    a_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Subdomain:
    name: str
    ip: Optional[str] = None


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    total_checked: int = 0
    error: Optional[str] = None


@dataclass
class EmailResult:
    domain: str
    emails: list[str] = field(default_factory=list)
    source: str = ""
    error: Optional[str] = None


@dataclass
class Technology:
    name: str
    category: Optional[str] = None
    version: Optional[str] = None


@dataclass
class TechResult:
    domain: str
    url: str
    technologies: list[Technology] = field(default_factory=list)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    error: Optional[str] = None


@dataclass
class OpenPort:
    port: int
    banner: Optional[str] = None


@dataclass
class PortScanResult:
    target: str
    open_ports: list[OpenPort] = field(default_factory=list)
    scanned_range: str = "1-1024"
    error: Optional[str] = None


@dataclass
class ShodanVuln:
    cve_id: str
    cvss: Optional[float] = None
    summary: Optional[str] = None


@dataclass
class ShodanHostInfo:
    ip: str
    org: Optional[str] = None
    os: Optional[str] = None
    ports: list[int] = field(default_factory=list)
    vulns: list[ShodanVuln] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    country: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ShodanResult:
    domain: str
    hosts: list[ShodanHostInfo] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class ReconResult:
    """Aggregate result passed to the report generator."""
    domain: str
    whois: Optional[WhoisResult] = None
    dns: Optional[DNSResult] = None
    subdomains: Optional[SubdomainResult] = None
    emails: Optional[EmailResult] = None
    tech: Optional[TechResult] = None
    port_scan: Optional[PortScanResult] = None
    shodan: Optional[ShodanResult] = None
