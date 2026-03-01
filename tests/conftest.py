"""Shared fixtures for OSINT tool tests."""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Disable time.sleep globally to speed up tests."""
    monkeypatch.setattr("time.sleep", lambda *a, **kw: None)


@pytest.fixture
def no_api_keys(monkeypatch):
    """Ensure all API keys are empty."""
    monkeypatch.setattr("config.HUNTER_API_KEY", "")
    monkeypatch.setattr("config.SHODAN_API_KEY", "")
    monkeypatch.setattr("config.BUILTWITH_API_KEY", "")


@pytest.fixture
def mock_whois_response():
    """A mock whois response object with realistic fields."""
    w = MagicMock()
    w.registrar = "Example Registrar, Inc."
    w.creation_date = datetime(2020, 1, 15, 12, 0, 0)
    w.expiration_date = datetime(2025, 1, 15, 12, 0, 0)
    w.updated_date = datetime(2024, 6, 1, 0, 0, 0)
    w.name_servers = ["ns1.example.com", "ns2.example.com"]
    w.org = "Example Corp"
    w.country = "US"
    w.emails = "admin@example.com"
    w.status = ["clientTransferProhibited"]
    return w


@pytest.fixture
def tmp_reports_dir(tmp_path, monkeypatch):
    """Temporary reports directory for report generator tests."""
    reports_dir = str(tmp_path / "reports")
    monkeypatch.setattr("config.REPORTS_DIR", reports_dir)
    return reports_dir


@pytest.fixture
def sample_html_wordpress():
    return """
    <html>
    <head><meta name="generator" content="WordPress 6.4"></head>
    <body>
        <link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">
        <script src="/wp-includes/js/jquery.min.js"></script>
    </body>
    </html>
    """


@pytest.fixture
def sample_html_react():
    return """
    <html>
    <head></head>
    <body>
        <div id="root" data-reactroot>
            <script src="/static/js/react.min.js"></script>
        </div>
    </body>
    </html>
    """
