"""Tests for config.py — env loading and path construction."""

import os
import config


class TestConfigDefaults:
    """Verify default values when env vars are not set."""

    def test_api_keys_default_empty(self):
        # Keys default to empty string when env vars not set
        assert isinstance(config.HUNTER_API_KEY, str)
        assert isinstance(config.SHODAN_API_KEY, str)
        assert isinstance(config.BUILTWITH_API_KEY, str)

    def test_rate_limits(self):
        assert config.RATE_LIMIT_DNS == 0.1
        assert config.RATE_LIMIT_HTTP == 1.5
        assert config.RATE_LIMIT_API == 1.0
        assert config.RATE_LIMIT_PORT_SCAN == 0.05

    def test_thread_counts(self):
        assert config.PORT_SCAN_THREADS == 100
        assert config.SUBDOMAIN_THREADS == 50

    def test_paths_are_absolute(self):
        assert os.path.isabs(config.BASE_DIR)
        assert os.path.isabs(config.WORDLIST_PATH)
        assert os.path.isabs(config.REPORTS_DIR)
        assert os.path.isabs(config.TEMPLATES_DIR)

    def test_base_dir_exists(self):
        assert os.path.isdir(config.BASE_DIR)

    def test_templates_dir_exists(self):
        assert os.path.isdir(config.TEMPLATES_DIR)
