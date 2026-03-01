"""Tests for report_generator.py — path traversal guard and report generation."""

import os
import pytest
from unittest.mock import patch, MagicMock
from modules.models import ReconResult, WhoisResult, DNSResult
from modules.report_generator import ReportGenerator


class TestFilenameSanitization:
    """Tests for filename sanitization and path traversal guard."""

    def test_normal_domain(self, tmp_reports_dir):
        recon = ReconResult(domain="example.com")
        gen = ReportGenerator()
        path = gen.generate(recon)
        assert os.path.basename(path) == "example_com_osint_report.html"
        assert path.startswith(tmp_reports_dir)
        assert os.path.exists(path)

    def test_subdomain(self, tmp_reports_dir):
        recon = ReconResult(domain="www.sub.example.com")
        gen = ReportGenerator()
        path = gen.generate(recon)
        assert os.path.basename(path) == "www_sub_example_com_osint_report.html"

    def test_slash_in_domain_sanitized(self, tmp_reports_dir):
        recon = ReconResult(domain="example.com/path")
        gen = ReportGenerator()
        path = gen.generate(recon)
        assert "/" not in os.path.basename(path).replace("_osint_report.html", "")
        assert path.startswith(tmp_reports_dir)

    def test_backslash_in_domain_sanitized(self, tmp_reports_dir):
        recon = ReconResult(domain="example.com\\path")
        gen = ReportGenerator()
        path = gen.generate(recon)
        assert "\\" not in os.path.basename(path)

    def test_path_traversal_dots_neutralized(self, tmp_reports_dir):
        recon = ReconResult(domain="../../../etc/passwd")
        gen = ReportGenerator()
        path = gen.generate(recon)
        # Dots and slashes are replaced with underscores
        assert path.startswith(tmp_reports_dir)
        assert os.path.exists(path)


class TestReportGeneration:
    """Tests for HTML report content."""

    def test_report_contains_domain(self, tmp_reports_dir):
        recon = ReconResult(domain="example.com")
        gen = ReportGenerator()
        path = gen.generate(recon)
        with open(path) as f:
            html = f.read()
        assert "example.com" in html

    def test_report_with_whois_data(self, tmp_reports_dir):
        recon = ReconResult(
            domain="example.com",
            whois=WhoisResult(
                domain="example.com",
                registrar="Test Registrar",
            ),
        )
        gen = ReportGenerator()
        path = gen.generate(recon)
        with open(path) as f:
            html = f.read()
        assert "Test Registrar" in html

    def test_report_with_dns_data(self, tmp_reports_dir):
        recon = ReconResult(
            domain="example.com",
            dns=DNSResult(
                domain="example.com",
                a_records=["93.184.216.34"],
            ),
        )
        gen = ReportGenerator()
        path = gen.generate(recon)
        with open(path) as f:
            html = f.read()
        assert "93.184.216.34" in html

    def test_report_creates_directory(self, tmp_reports_dir):
        """Reports dir is created if it doesn't exist."""
        assert not os.path.exists(tmp_reports_dir)
        recon = ReconResult(domain="example.com")
        gen = ReportGenerator()
        gen.generate(recon)
        assert os.path.isdir(tmp_reports_dir)

    def test_report_has_autoescape(self):
        """Verify Jinja2 autoescape is enabled (XSS protection)."""
        gen = ReportGenerator()
        assert gen.env.autoescape is True
