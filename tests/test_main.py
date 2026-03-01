"""Tests for main.py — domain sanitization, CLI, and disclaimer."""

import argparse
import pytest
from unittest.mock import patch, MagicMock


class TestDomainSanitization:
    """Tests for the domain input sanitization in run()."""

    def _sanitize(self, raw_domain: str) -> str:
        """Extract the sanitization logic from run() for isolated testing."""
        domain = raw_domain.lower().strip()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break
        domain = domain.rstrip("/")
        return domain

    def test_bare_domain(self):
        assert self._sanitize("example.com") == "example.com"

    def test_https_prefix(self):
        assert self._sanitize("https://example.com") == "example.com"

    def test_http_prefix(self):
        assert self._sanitize("http://example.com") == "example.com"

    def test_trailing_slash(self):
        assert self._sanitize("example.com/") == "example.com"

    def test_https_with_trailing_slash(self):
        assert self._sanitize("https://example.com/") == "example.com"

    def test_uppercase(self):
        assert self._sanitize("EXAMPLE.COM") == "example.com"

    def test_uppercase_with_prefix(self):
        assert self._sanitize("HTTPS://EXAMPLE.COM/") == "example.com"

    def test_whitespace(self):
        assert self._sanitize("  example.com  ") == "example.com"

    def test_ftp_not_stripped(self):
        """ftp:// is NOT a recognized prefix and should remain."""
        assert self._sanitize("ftp://example.com") == "ftp://example.com"

    def test_stripe_not_corrupted(self):
        """Regression: lstrip('https://') would corrupt 'stripe.com' to 'ripe.com'."""
        assert self._sanitize("https://stripe.com") == "stripe.com"

    def test_shop_not_corrupted(self):
        """Regression: lstrip('https://') would corrupt 'shop.com' to 'op.com'."""
        assert self._sanitize("https://shop.com") == "shop.com"

    def test_test_not_corrupted(self):
        """Regression: lstrip('https://') would corrupt 'test.com' to 'est.com'."""
        assert self._sanitize("https://test.com") == "test.com"

    def test_empty_after_strip(self):
        assert self._sanitize("https:///") == ""

    def test_subdomain(self):
        assert self._sanitize("https://www.example.com") == "www.example.com"

    def test_multiple_trailing_slashes(self):
        assert self._sanitize("https://example.com///") == "example.com"


class TestConfirmDisclaimer:
    """Tests for the confirm_disclaimer function."""

    @patch("builtins.input", return_value="yes")
    def test_yes_accepted(self, mock_input):
        from main import confirm_disclaimer
        assert confirm_disclaimer() is True

    @patch("builtins.input", return_value="y")
    def test_y_accepted(self, mock_input):
        from main import confirm_disclaimer
        assert confirm_disclaimer() is True

    @patch("builtins.input", return_value="YES")
    def test_uppercase_yes_accepted(self, mock_input):
        from main import confirm_disclaimer
        assert confirm_disclaimer() is True

    @patch("builtins.input", return_value="no")
    def test_no_rejected(self, mock_input):
        from main import confirm_disclaimer
        assert confirm_disclaimer() is False

    @patch("builtins.input", return_value="")
    def test_empty_rejected(self, mock_input):
        from main import confirm_disclaimer
        assert confirm_disclaimer() is False


class TestMainCLI:
    """Tests for CLI argument parsing."""

    def test_no_modules_raises_error(self):
        from main import main
        with patch("sys.argv", ["main.py", "--domain", "example.com"]):
            with pytest.raises(SystemExit):
                main()

    @patch("builtins.input", return_value="no")
    def test_disclaimer_rejected_exits(self, mock_input):
        from main import main
        with patch("sys.argv", ["main.py", "--domain", "example.com", "--dns"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    @patch("main.run")
    @patch("builtins.input", return_value="yes")
    def test_disclaimer_accepted_runs(self, mock_input, mock_run):
        from main import main
        with patch("sys.argv", ["main.py", "--domain", "example.com", "--dns"]):
            main()
        mock_run.assert_called_once()

    @patch("main.run")
    def test_yes_flag_skips_disclaimer(self, mock_run):
        from main import main
        with patch("sys.argv", ["main.py", "--domain", "example.com", "--dns", "--yes"]):
            main()
        mock_run.assert_called_once()


class TestRunFunction:
    """Tests for the run() orchestration function."""

    def _make_args(self, domain="example.com", all_flag=False, **flags):
        args = argparse.Namespace(
            domain=domain, all=all_flag, no_open=True,
            whois=flags.get("whois", False),
            dns=flags.get("dns", False),
            subdomains=flags.get("subdomains", False),
            emails=flags.get("emails", False),
            tech=flags.get("tech", False),
            ports=flags.get("ports", False),
            shodan=flags.get("shodan", False),
        )
        return args

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.whois_lookup.WhoisLookup")
    def test_whois_only(self, mock_whois_cls, mock_report_cls):
        from main import run
        from modules.models import WhoisResult
        mock_whois_cls.return_value.run.return_value = WhoisResult(
            domain="example.com", registrar="Test Registrar"
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(whois=True)
        run(args)

        mock_whois_cls.return_value.run.assert_called_once_with("example.com")

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.dns_enum.DNSEnum")
    def test_dns_only(self, mock_dns_cls, mock_report_cls):
        from main import run
        from modules.models import DNSResult
        mock_dns_cls.return_value.run.return_value = DNSResult(
            domain="example.com", a_records=["1.2.3.4"]
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(dns=True)
        run(args)

        mock_dns_cls.return_value.run.assert_called_once_with("example.com")

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.subdomain_bruteforce.SubdomainBruteforce")
    def test_subdomains_only(self, mock_sub_cls, mock_report_cls):
        from main import run
        from modules.models import SubdomainResult
        mock_sub_cls.return_value.run.return_value = SubdomainResult(
            domain="example.com", total_checked=100
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(subdomains=True)
        run(args)

        mock_sub_cls.return_value.run.assert_called_once_with("example.com")

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.email_harvest.EmailHarvest")
    def test_emails_only(self, mock_email_cls, mock_report_cls):
        from main import run
        from modules.models import EmailResult
        mock_email_cls.return_value.run.return_value = EmailResult(
            domain="example.com", source="Hunter.io"
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(emails=True)
        run(args)

        mock_email_cls.return_value.run.assert_called_once_with("example.com")

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.tech_fingerprint.TechFingerprint")
    def test_tech_only(self, mock_tech_cls, mock_report_cls):
        from main import run
        from modules.models import TechResult, Technology
        mock_tech_cls.return_value.run.return_value = TechResult(
            domain="example.com", url="https://example.com",
            technologies=[Technology(name="Nginx", category="Web Server")],
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(tech=True)
        run(args)

        mock_tech_cls.return_value.run.assert_called_once_with("example.com")

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.port_scanner.PortScanner")
    def test_ports_only(self, mock_port_cls, mock_report_cls):
        from main import run
        from modules.models import PortScanResult
        mock_port_cls.return_value.run.return_value = PortScanResult(target="example.com")
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(ports=True)
        run(args)

        mock_port_cls.return_value.run.assert_called_once()

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.shodan_lookup.ShodanLookup")
    def test_shodan_only(self, mock_shodan_cls, mock_report_cls):
        from main import run
        from modules.models import ShodanResult
        mock_shodan_cls.return_value.run.return_value = ShodanResult(domain="example.com")
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(shodan=True)
        run(args)

        mock_shodan_cls.return_value.run.assert_called_once()

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.whois_lookup.WhoisLookup")
    def test_error_in_module_prints_warning(self, mock_whois_cls, mock_report_cls):
        from main import run
        from modules.models import WhoisResult
        mock_whois_cls.return_value.run.return_value = WhoisResult(
            domain="example.com", error="WHOIS query failed"
        )
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(whois=True)
        run(args)  # Should not raise

    @patch("modules.report_generator.ReportGenerator")
    @patch("modules.whois_lookup.WhoisLookup")
    def test_domain_sanitized_in_run(self, mock_whois_cls, mock_report_cls):
        from main import run
        from modules.models import WhoisResult
        mock_whois_cls.return_value.run.return_value = WhoisResult(domain="stripe.com")
        mock_report_cls.return_value.generate.return_value = "/tmp/report.html"

        args = self._make_args(domain="https://stripe.com", whois=True)
        run(args)

        mock_whois_cls.return_value.run.assert_called_once_with("stripe.com")
