"""Tests for modules/shodan_lookup.py."""

import socket
import pytest
from unittest.mock import patch, MagicMock
import shodan
from modules.shodan_lookup import ShodanLookup


class TestShodanAPIKeyGate:
    """API key must be present or module returns early with error."""

    @patch("config.SHODAN_API_KEY", "")
    def test_no_key_returns_error(self):
        result = ShodanLookup().run("example.com")

        assert result.error == "SHODAN_API_KEY not set"
        assert result.hosts == []


class TestShodanLookupIP:

    @patch("config.SHODAN_API_KEY", "test-key")
    def test_success_with_vulns_as_list(self):
        mock_api = MagicMock()
        mock_api.host.return_value = {
            "org": "Example Corp",
            "os": "Linux",
            "country_name": "US",
            "ports": [22, 80, 443],
            "hostnames": ["example.com"],
            "vulns": ["CVE-2024-1234", "CVE-2024-5678"],
        }

        info = ShodanLookup()._lookup_ip(mock_api, "93.184.216.34")

        assert info.org == "Example Corp"
        assert info.os == "Linux"
        assert info.country == "US"
        assert info.ports == [22, 80, 443]
        assert len(info.vulns) == 2
        assert info.vulns[0].cve_id == "CVE-2024-1234"

    @patch("config.SHODAN_API_KEY", "test-key")
    def test_success_with_vulns_as_dict(self):
        mock_api = MagicMock()
        mock_api.host.return_value = {
            "org": "Example Corp",
            "os": None,
            "country_name": None,
            "ports": [80],
            "hostnames": [],
            "vulns": {
                "CVE-2024-9999": {"cvss": 9.8, "summary": "Critical RCE vulnerability"},
                "CVE-2024-1111": {"cvss": 4.3, "summary": "Info disclosure"},
            },
        }

        info = ShodanLookup()._lookup_ip(mock_api, "1.2.3.4")

        assert len(info.vulns) == 2
        # Sorted by CVSS descending
        assert info.vulns[0].cve_id == "CVE-2024-9999"
        assert info.vulns[0].cvss == 9.8
        assert info.vulns[1].cve_id == "CVE-2024-1111"

    @patch("config.SHODAN_API_KEY", "test-key")
    def test_no_vulns(self):
        mock_api = MagicMock()
        mock_api.host.return_value = {
            "org": "Example Corp",
            "os": None,
            "country_name": None,
            "ports": [],
            "hostnames": [],
        }

        info = ShodanLookup()._lookup_ip(mock_api, "1.2.3.4")

        assert info.vulns == []

    @patch("config.SHODAN_API_KEY", "test-key")
    def test_api_error(self):
        mock_api = MagicMock()
        mock_api.host.side_effect = shodan.APIError("No information available")

        info = ShodanLookup()._lookup_ip(mock_api, "1.2.3.4")

        assert info.error == "No information available"


class TestShodanRun:

    @patch("modules.shodan_lookup.shodan.Shodan")
    @patch("config.SHODAN_API_KEY", "test-key")
    def test_with_provided_ips(self, mock_shodan_cls):
        mock_api = MagicMock()
        mock_api.host.return_value = {
            "org": "Test", "os": None, "country_name": None,
            "ports": [], "hostnames": [],
        }
        mock_shodan_cls.return_value = mock_api

        result = ShodanLookup().run("example.com", ips=["1.2.3.4"])

        assert len(result.hosts) == 1
        assert result.hosts[0].ip == "1.2.3.4"

    @patch("modules.shodan_lookup.socket.getaddrinfo")
    @patch("modules.shodan_lookup.shodan.Shodan")
    @patch("config.SHODAN_API_KEY", "test-key")
    def test_resolves_ips_when_not_provided(self, mock_shodan_cls, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, None, None, None, ("93.184.216.34", 0)),
        ]
        mock_api = MagicMock()
        mock_api.host.return_value = {
            "org": "Test", "os": None, "country_name": None,
            "ports": [], "hostnames": [],
        }
        mock_shodan_cls.return_value = mock_api

        result = ShodanLookup().run("example.com")

        assert len(result.hosts) == 1

    @patch("modules.shodan_lookup.socket.getaddrinfo")
    @patch("config.SHODAN_API_KEY", "test-key")
    def test_dns_resolution_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("DNS failed")

        result = ShodanLookup().run("nonexistent.invalid")

        assert "Cannot resolve" in result.error
