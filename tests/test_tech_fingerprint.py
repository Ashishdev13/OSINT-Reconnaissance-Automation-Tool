"""Tests for modules/tech_fingerprint.py."""

import pytest
from unittest.mock import patch, MagicMock
import requests
from modules.tech_fingerprint import TechFingerprint, TECH_PATTERNS


class TestPatternMatch:
    """Tests for _pattern_match against sample HTML/headers."""

    def _make_response(self, html="", headers=None):
        resp = MagicMock()
        resp.text = html
        resp.headers = headers or {}
        return resp

    def test_wordpress_html(self, sample_html_wordpress):
        resp = self._make_response(html=sample_html_wordpress)
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "WordPress" in names

    def test_react_html(self, sample_html_react):
        resp = self._make_response(html=sample_html_react)
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "React" in names

    def test_nginx_header(self):
        resp = self._make_response(headers={"Server": "nginx/1.24.0"})
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "Nginx" in names

    def test_cloudflare_headers(self):
        resp = self._make_response(headers={
            "Server": "cloudflare",
            "CF-Ray": "abc123",
        })
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "Cloudflare" in names

    def test_php_header(self):
        resp = self._make_response(headers={"X-Powered-By": "PHP/8.2"})
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "PHP" in names

    def test_jquery_html(self):
        html = '<script src="/js/jquery.min.js"></script>'
        resp = self._make_response(html=html)
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "jQuery" in names

    def test_nextjs_html(self):
        html = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
        resp = self._make_response(html=html)
        techs = TechFingerprint()._pattern_match(resp)
        names = [t.name for t in techs]
        assert "Next.js" in names

    def test_no_match(self):
        resp = self._make_response(html="<html><body>Hello</body></html>")
        techs = TechFingerprint()._pattern_match(resp)
        assert techs == []

    def test_all_patterns_have_category(self):
        for name, pattern in TECH_PATTERNS.items():
            assert "category" in pattern, f"{name} missing category"


class TestTechFingerprintRun:

    @patch("modules.tech_fingerprint.requests.Session")
    def test_success(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.url = "https://example.com"
        mock_resp.text = '<script src="/js/jquery.min.js"></script>'
        mock_resp.headers = {"Server": "nginx/1.24.0"}
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        result = TechFingerprint().run("example.com")

        assert result.error is None
        assert result.server == "nginx/1.24.0"
        names = [t.name for t in result.technologies]
        assert "Nginx" in names
        assert "jQuery" in names

    @patch("modules.tech_fingerprint.requests.Session")
    def test_ssl_fallback_to_http(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.url = "http://example.com"
        mock_resp.text = ""
        mock_resp.headers = {"Server": "Apache"}

        def get_side_effect(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.SSLError("SSL failed")
            return mock_resp

        mock_session.get.side_effect = get_side_effect
        mock_session_cls.return_value = mock_session

        result = TechFingerprint().run("example.com")

        assert result.error is None
        assert result.server == "Apache"

    @patch("modules.tech_fingerprint.requests.Session")
    def test_connection_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Failed")
        mock_session_cls.return_value = mock_session

        result = TechFingerprint().run("example.com")

        assert result.error is not None

    @patch("config.BUILTWITH_API_KEY", "")
    def test_builtwith_no_key(self):
        result = TechFingerprint()._builtwith("example.com")
        assert result == []

    @patch("modules.tech_fingerprint.requests.get")
    @patch("config.BUILTWITH_API_KEY", "test-bw-key")
    def test_builtwith_success(self, mock_get):
        mock_get.return_value.json.return_value = {
            "Results": [{
                "Result": {
                    "Paths": [{
                        "Technologies": [
                            {"Name": "jQuery", "Categories": ["JavaScript"]},
                            {"Name": "Nginx", "Categories": ["Web Server"]},
                        ]
                    }]
                }
            }]
        }
        mock_get.return_value.raise_for_status = MagicMock()

        result = TechFingerprint()._builtwith("example.com")

        assert len(result) == 2
        assert result[0].name == "jQuery"
        assert result[0].category == "JavaScript"

    @patch("modules.tech_fingerprint.requests.get")
    @patch("config.BUILTWITH_API_KEY", "test-bw-key")
    def test_builtwith_api_error(self, mock_get):
        mock_get.side_effect = Exception("API failed")

        result = TechFingerprint()._builtwith("example.com")

        assert result == []

    @patch("modules.tech_fingerprint.requests.Session")
    def test_deduplicates_builtwith_and_pattern(self, mock_session_cls):
        """BuiltWith results are deduplicated against pattern-matched ones."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.url = "https://example.com"
        mock_resp.text = '<script src="/js/jquery.min.js"></script>'
        mock_resp.headers = {}
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        with patch.object(TechFingerprint, "_builtwith") as mock_bw:
            from modules.models import Technology
            mock_bw.return_value = [
                Technology(name="jQuery", category="JS"),  # duplicate
                Technology(name="Redis", category="Database"),  # new
            ]
            result = TechFingerprint().run("example.com")

        names = [t.name for t in result.technologies]
        assert names.count("jQuery") == 1
        assert "Redis" in names

    @patch("modules.tech_fingerprint.requests.Session")
    def test_max_redirects_set(self, mock_session_cls):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.url = "https://example.com"
        mock_resp.text = ""
        mock_resp.headers = {}
        mock_session.get.return_value = mock_resp
        mock_session_cls.return_value = mock_session

        TechFingerprint().run("example.com")

        assert mock_session.max_redirects == 5
