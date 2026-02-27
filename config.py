"""
Configuration loader for OSINT Reconnaissance Automation Tool.
Loads API keys and settings from environment / .env file.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
HUNTER_API_KEY: str = os.getenv("HUNTER_API_KEY", "")
SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
BUILTWITH_API_KEY: str = os.getenv("BUILTWITH_API_KEY", "")

# Rate limiting (seconds between requests)
RATE_LIMIT_DNS: float = 0.1
RATE_LIMIT_HTTP: float = 1.5
RATE_LIMIT_API: float = 1.0
RATE_LIMIT_PORT_SCAN: float = 0.05

# Port scanning
PORT_SCAN_THREADS: int = 100
PORT_SCAN_TIMEOUT: float = 0.5

# Subdomain brute-force
SUBDOMAIN_THREADS: int = 50
SUBDOMAIN_TIMEOUT: float = 2.0

# Paths
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH: str = os.path.join(BASE_DIR, "wordlists", "subdomains-top1million-5000.txt")
REPORTS_DIR: str = os.path.join(BASE_DIR, "reports")
TEMPLATES_DIR: str = os.path.join(BASE_DIR, "templates")
