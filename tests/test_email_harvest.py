"""Tests for modules/email_harvest.py."""

import pytest
from unittest.mock import patch, MagicMock
from modules.email_harvest import EmailHarvest, _EMAIL_RE


class TestEmailRegex:
    """Tests for the email regex pattern."""

    def test_standard_email(self):
        assert _EMAIL_RE.search("user@example.com")

    def test_email_with_dots(self):
        assert _EMAIL_RE.search("first.last@example.com")

    def test_email_with_plus(self):
        assert _EMAIL_RE.search("user+tag@example.com")

    def test_email_with_hyphen(self):
        assert _EMAIL_RE.search("user-name@example.com")

    def test_no_match_without_at(self):
        assert _EMAIL_RE.search("not-an-email") is None

    def test_no_match_without_tld(self):
        assert _EMAIL_RE.search("user@localhost") is None


class TestHunterIO:

    @patch("config.HUNTER_API_KEY", "")
    def test_no_api_key_returns_empty(self):
        result = EmailHarvest()._hunter_io("example.com")
        assert result == []

    @patch("modules.email_harvest.requests.get")
    @patch("config.HUNTER_API_KEY", "test-key-123")
    def test_success(self, mock_get):
        mock_get.return_value.json.return_value = {
            "data": {
                "emails": [
                    {"value": "admin@example.com"},
                    {"value": "info@example.com"},
                ]
            }
        }
        mock_get.return_value.raise_for_status = MagicMock()

        result = EmailHarvest()._hunter_io("example.com")

        assert result == ["admin@example.com", "info@example.com"]

    @patch("modules.email_harvest.requests.get")
    @patch("config.HUNTER_API_KEY", "test-key-123")
    def test_api_error_returns_empty(self, mock_get):
        mock_get.side_effect = Exception("API error")

        result = EmailHarvest()._hunter_io("example.com")

        assert result == []


class TestGoogleScrape:

    @patch("modules.email_harvest.requests.Session")
    def test_finds_emails_in_html(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Contact us at admin@example.com or sales@example.com</body></html>'
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        result = EmailHarvest()._google_scrape("example.com")

        assert "admin@example.com" in result
        assert "sales@example.com" in result

    @patch("modules.email_harvest.requests.Session")
    def test_filters_to_target_domain(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>admin@example.com other@gmail.com</body></html>'
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        result = EmailHarvest()._google_scrape("example.com")

        assert "admin@example.com" in result
        assert "other@gmail.com" not in result

    @patch("modules.email_harvest.requests.Session")
    def test_429_stops_scraping(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = ""
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        result = EmailHarvest()._google_scrape("example.com")

        assert result == []
        # Should only make one call before stopping
        assert mock_session.get.call_count == 1


class TestEmailHarvestRun:

    @patch.object(EmailHarvest, "_google_scrape", return_value=[])
    @patch.object(EmailHarvest, "_hunter_io", return_value=["admin@example.com"])
    def test_hunter_only(self, mock_hunter, mock_google):
        result = EmailHarvest().run("example.com")

        assert "admin@example.com" in result.emails
        assert "Hunter.io" in result.source
        assert "Google" not in result.source

    @patch.object(EmailHarvest, "_google_scrape", return_value=["info@example.com"])
    @patch.object(EmailHarvest, "_hunter_io", return_value=[])
    def test_google_only(self, mock_hunter, mock_google):
        result = EmailHarvest().run("example.com")

        assert "info@example.com" in result.emails
        assert "Google" in result.source

    @patch.object(EmailHarvest, "_google_scrape", return_value=["admin@example.com"])
    @patch.object(EmailHarvest, "_hunter_io", return_value=["admin@example.com"])
    def test_deduplication(self, mock_hunter, mock_google):
        result = EmailHarvest().run("example.com")

        assert len(result.emails) == 1

    @patch.object(EmailHarvest, "_google_scrape", return_value=[])
    @patch.object(EmailHarvest, "_hunter_io", return_value=[])
    def test_no_results(self, mock_hunter, mock_google):
        result = EmailHarvest().run("example.com")

        assert result.emails == []
        assert result.source == "None"
