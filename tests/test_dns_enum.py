"""Tests for modules/dns_enum.py."""

import pytest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
from modules.dns_enum import DNSEnum


class TestDNSQuery:
    """Tests for the _query helper method."""

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_a_record_query(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "93.184.216.34"
        mock_resolve.return_value = [mock_answer]

        result = DNSEnum()._query("example.com", "A")

        assert result == ["93.184.216.34"]
        mock_resolve.assert_called_once_with("example.com", "A", lifetime=5)

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_trailing_dot_stripped(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "ns1.example.com."
        mock_resolve.return_value = [mock_answer]

        result = DNSEnum()._query("example.com", "NS")

        assert result == ["ns1.example.com"]

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_nxdomain_returns_empty(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = DNSEnum()._query("nonexistent.invalid", "A")

        assert result == []

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_no_answer_returns_empty(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        result = DNSEnum()._query("example.com", "AAAA")

        assert result == []

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_timeout_returns_empty(self, mock_resolve):
        mock_resolve.side_effect = dns.exception.Timeout()

        result = DNSEnum()._query("example.com", "A")

        assert result == []

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_generic_exception_returns_empty(self, mock_resolve):
        mock_resolve.side_effect = Exception("DNS failure")

        result = DNSEnum()._query("example.com", "A")

        assert result == []


class TestDNSEnumRun:
    """Tests for the run() orchestration method."""

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_all_record_types_queried(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "test"
        mock_resolve.return_value = [mock_answer]

        result = DNSEnum().run("example.com")

        assert result.error is None
        # All record types should have been queried
        record_types = [c[0][1] for c in mock_resolve.call_args_list]
        assert "A" in record_types
        assert "MX" in record_types
        assert "NS" in record_types
        assert "TXT" in record_types
        assert "CNAME" in record_types

    @patch("modules.dns_enum.dns.resolver.resolve")
    def test_partial_failure(self, mock_resolve):
        """Some record types may fail while others succeed."""
        def side_effect(domain, rtype, **kw):
            if rtype == "A":
                answer = MagicMock()
                answer.to_text.return_value = "1.2.3.4"
                return [answer]
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = side_effect

        result = DNSEnum().run("example.com")

        assert result.a_records == ["1.2.3.4"]
        assert result.mx_records == []
        assert result.error is None
