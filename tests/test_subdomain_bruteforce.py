"""Tests for modules/subdomain_bruteforce.py."""

import socket
import pytest
from unittest.mock import patch, MagicMock, mock_open
from modules.subdomain_bruteforce import SubdomainBruteforce


class TestResolve:
    """Tests for _resolve method."""

    @patch("modules.subdomain_bruteforce.socket.gethostbyname")
    def test_resolve_success(self, mock_resolve):
        mock_resolve.return_value = "93.184.216.34"

        fqdn, ip = SubdomainBruteforce()._resolve("www.example.com")

        assert fqdn == "www.example.com"
        assert ip == "93.184.216.34"

    @patch("modules.subdomain_bruteforce.socket.gethostbyname")
    def test_resolve_failure(self, mock_resolve):
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")

        fqdn, ip = SubdomainBruteforce()._resolve("nonexistent.example.com")

        assert fqdn == "nonexistent.example.com"
        assert ip is None


class TestLoadWordlist:
    """Tests for _load_wordlist method."""

    @patch("builtins.open", mock_open(read_data="www\nmail\nftp\n# comment\n\n"))
    def test_loads_and_filters(self):
        words = SubdomainBruteforce()._load_wordlist()

        assert words == ["www", "mail", "ftp"]

    @patch("builtins.open", side_effect=FileNotFoundError())
    def test_missing_wordlist_returns_empty(self, mock_file):
        words = SubdomainBruteforce()._load_wordlist()

        assert words == []


class TestSubdomainRun:
    """Tests for run() method."""

    @patch("builtins.open", side_effect=FileNotFoundError())
    def test_missing_wordlist_sets_error(self, mock_file):
        result = SubdomainBruteforce().run("example.com")

        assert result.error == "Wordlist not found"
        assert result.subdomains == []

    @patch("modules.subdomain_bruteforce.tqdm")
    @patch("modules.subdomain_bruteforce.socket.gethostbyname")
    @patch("builtins.open", mock_open(read_data="www\nmail\nnonexistent\n"))
    def test_finds_subdomains(self, mock_resolve, mock_tqdm):
        def resolve_side_effect(fqdn):
            lookup = {
                "www.example.com": "1.2.3.4",
                "mail.example.com": "1.2.3.5",
            }
            if fqdn in lookup:
                return lookup[fqdn]
            raise socket.gaierror("Not found")

        mock_resolve.side_effect = resolve_side_effect
        mock_tqdm.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_tqdm.return_value.__exit__ = MagicMock(return_value=False)

        result = SubdomainBruteforce().run("example.com")

        assert result.error is None
        assert result.total_checked == 3
        assert len(result.subdomains) == 2
        names = [s.name for s in result.subdomains]
        assert "mail" in names
        assert "www" in names
