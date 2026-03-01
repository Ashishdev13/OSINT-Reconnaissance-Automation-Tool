"""Tests for modules/whois_lookup.py."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from modules.whois_lookup import WhoisLookup


class TestWhoisLookup:

    @patch("modules.whois_lookup.whois.whois")
    def test_success(self, mock_whois, mock_whois_response):
        mock_whois.return_value = mock_whois_response

        result = WhoisLookup().run("example.com")

        assert result.error is None
        assert result.registrar == "Example Registrar, Inc."
        assert result.registrant_org == "Example Corp"
        assert result.registrant_country == "US"

    @patch("modules.whois_lookup.whois.whois")
    def test_datetime_formatting(self, mock_whois, mock_whois_response):
        mock_whois.return_value = mock_whois_response

        result = WhoisLookup().run("example.com")

        assert result.creation_date == "2020-01-15 12:00:00 UTC"
        assert result.expiration_date == "2025-01-15 12:00:00 UTC"

    @patch("modules.whois_lookup.whois.whois")
    def test_list_first_element(self, mock_whois):
        w = MagicMock()
        w.registrar = ["Primary Registrar", "Secondary"]
        w.creation_date = [datetime(2020, 1, 1), datetime(2019, 1, 1)]
        w.expiration_date = None
        w.updated_date = None
        w.name_servers = None
        w.org = None
        w.country = None
        w.emails = None
        w.status = None
        mock_whois.return_value = w

        result = WhoisLookup().run("example.com")

        assert result.registrar == "Primary Registrar"
        assert result.creation_date == "2020-01-01 00:00:00 UTC"

    @patch("modules.whois_lookup.whois.whois")
    def test_none_values(self, mock_whois):
        w = MagicMock()
        w.registrar = None
        w.creation_date = None
        w.expiration_date = None
        w.updated_date = None
        w.name_servers = None
        w.org = None
        w.country = None
        w.emails = None
        w.status = None
        mock_whois.return_value = w

        result = WhoisLookup().run("example.com")

        assert result.error is None
        assert result.registrar is None
        assert result.name_servers == []
        assert result.status == []

    @patch("modules.whois_lookup.whois.whois")
    def test_name_servers_lowercased(self, mock_whois, mock_whois_response):
        mock_whois_response.name_servers = ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
        mock_whois.return_value = mock_whois_response

        result = WhoisLookup().run("example.com")

        assert result.name_servers == ["ns1.example.com", "ns2.example.com"]

    @patch("modules.whois_lookup.whois.whois")
    def test_exception_sets_error(self, mock_whois):
        mock_whois.side_effect = Exception("WHOIS query failed")

        result = WhoisLookup().run("example.com")

        assert result.error == "WHOIS query failed"
        assert result.registrar is None
