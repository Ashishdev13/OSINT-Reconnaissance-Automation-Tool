# OSINT Reconnaissance Automation Tool

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Purpose](https://img.shields.io/badge/Purpose-Educational%20%2F%20Authorized%20Use-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> **For educational and authorized security research only.**
> Unauthorized use against systems you do not own is illegal.

---

## What Is This?

The **OSINT Reconnaissance Automation Tool** is a modular, Python-based open-source intelligence (OSINT) framework that automates passive and active information gathering against a target domain. It consolidates eight distinct reconnaissance techniques into a single CLI tool, then renders all findings into a clean, dark-themed HTML report.

This project was built to demonstrate how security professionals perform the **reconnaissance phase** of a penetration test - the critical first step in understanding an organization's internet-facing attack surface before any active exploitation is attempted.

---

## Security Concepts Demonstrated

| Concept | Description |
|---------|-------------|
| **OSINT Methodology** | Structured intelligence gathering from publicly available sources without touching target systems directly |
| **Passive Reconnaissance** | WHOIS lookups, DNS record queries, and email harvesting - all conducted against public databases and APIs, leaving no footprint on the target |
| **Active Reconnaissance** | Port scanning and subdomain brute-forcing that directly interact with target infrastructure (requires explicit authorization) |
| **DNS Enumeration** | Mapping A, MX, NS, TXT, and CNAME records to understand mail infrastructure, CDN providers, and third-party services |
| **Subdomain Discovery** | Brute-force resolution of subdomains using a curated wordlist - surfaces hidden admin panels, staging environments, and forgotten services |
| **WHOIS Intelligence** | Extracting registrar, registrant, creation/expiry dates, and name servers to build an ownership profile and identify potential domain squatting |
| **Email Harvesting** | Collecting corporate email addresses via APIs and search engines - these are primary targets for phishing and credential stuffing |
| **Technology Fingerprinting** | Identifying web frameworks, CMS platforms, CDN providers, and analytics tools from HTTP headers and HTML patterns - narrows the attack surface |
| **Port Scanning** | Discovering open TCP ports to map exposed services and identify potentially unnecessary or unpatched network daemons |
| **Vulnerability Correlation** | Using the Shodan API to match discovered IPs against known CVEs - connects passive intel to real-world exploitability |
| **Rate Limiting** | Built-in request throttling to demonstrate responsible, non-disruptive reconnaissance practices |
| **Modular Architecture** | Each recon technique is an independent module - mirrors real-world tool design in frameworks like Recon-ng and Spiderfoot |

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Language** | Python 3.10+ | Core runtime |
| **WHOIS** | `python-whois` | Domain registration queries |
| **DNS** | `dnspython` | Record resolution (A/MX/NS/TXT/CNAME) |
| **HTTP** | `requests` | API calls and web scraping |
| **HTML Parsing** | `beautifulsoup4` | Google search scrape parsing |
| **Email Intel** | Hunter.io REST API | Corporate email discovery |
| **Vuln Intel** | Shodan REST API | CVE and host intelligence |
| **Tech Detection** | BuiltWith API (optional) | Additional technology fingerprinting |
| **Port Scanning** | `socket` (stdlib) | Raw TCP connection probing |
| **Threading** | `concurrent.futures` | Parallel port scan and subdomain brute-force |
| **Templating** | `Jinja2` | HTML report generation |
| **CLI** | `argparse` (stdlib) | Command-line interface |
| **Progress** | `tqdm` | Real-time progress bars |
| **Terminal UI** | `colorama` | Cross-platform colored output |
| **Config** | `python-dotenv` | Secure API key management from `.env` |

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Ashishdev13/OSINT-Reconnaissance-Automation-Tool.git
cd OSINT-Reconnaissance-Automation-Tool

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download the subdomain wordlist (SecLists top 5000)
python download_wordlist.py

# 5. Set up API keys
cp .env.example .env
# Open .env and add your keys (all optional - modules degrade gracefully)
```

### API Keys (Optional but Recommended)

| Key | Where to Get | Free Tier |
|-----|-------------|-----------|
| `HUNTER_API_KEY` | [hunter.io/api-keys](https://hunter.io/api-keys) | 25 searches/month |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Free with registration |
| `BUILTWITH_API_KEY` | [api.builtwith.com](https://api.builtwith.com/) | Limited free tier |

All modules degrade gracefully when API keys are absent - the tool still runs using non-API methods.

---

## Usage

```bash
# Run all recon modules against a domain
python main.py --domain example.com --all

# Run only passive modules (no direct target contact)
python main.py --domain example.com --whois --dns --emails

# Run tech fingerprinting and port scan
python main.py --domain example.com --tech --ports

# Port scan + Shodan CVE lookup
python main.py --domain example.com --ports --shodan

# Full recon, skip browser auto-open
python main.py --domain example.com --all --no-open

# Non-interactive mode (for scripts/CI)
python main.py --domain example.com --all --yes
```

### CLI Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--domain` | `-d` | Target domain name (required) |
| `--all` | `-a` | Run all recon modules |
| `--whois` | | WHOIS registration lookup |
| `--dns` | | DNS record enumeration |
| `--subdomains` | | Subdomain brute-force (wordlist) |
| `--emails` | | Email address harvesting |
| `--tech` | | Technology fingerprinting |
| `--ports` | | Port scan (TCP 1–1024) |
| `--shodan` | | Shodan CVE/host intelligence |
| `--no-open` | | Don't auto-open HTML report |
| `--yes` | `-y` | Skip ethical use disclaimer prompt |

### Run Individual Modules

Each module can be invoked standalone for quick, focused recon:

```bash
python -m modules.whois_lookup example.com
python -m modules.dns_enum example.com
python -m modules.subdomain_bruteforce example.com
python -m modules.email_harvest example.com
python -m modules.tech_fingerprint example.com
python -m modules.port_scanner example.com
python -m modules.shodan_lookup example.com
```

---

## Output

The tool generates a self-contained **dark-themed HTML report** saved to `reports/<domain>_osint_report.html` and automatically opens it in your default browser.

The report includes:
- **Summary bar** - quick stats (IPs, subdomains, emails, open ports, CVE count)
- **WHOIS** - registrar, dates, name servers, registrant info
- **DNS Records** - all record types in tagged format
- **Subdomains** - discovered subdomains with resolved IPs
- **Emails** - harvested addresses with sources
- **Technology Stack** - detected frameworks, servers, and tools
- **Open Ports** - port number, service name, and banner
- **Shodan Intelligence** - per-IP CVE list with CVSS scores and NVD links

---

## Project Structure

```
OSINT-Reconnaissance-Automation-Tool/
├── main.py                         # CLI entry point + orchestration
├── config.py                       # API keys, rate limits, file paths
├── download_wordlist.py            # SecLists wordlist downloader
├── requirements.txt                # Python dependencies
├── .env.example                    # API key template (copy to .env)
├── modules/
│   ├── models.py                   # Shared dataclasses (ReconResult, etc.)
│   ├── whois_lookup.py             # WHOIS module
│   ├── dns_enum.py                 # DNS enumeration module
│   ├── subdomain_bruteforce.py     # Subdomain brute-force module
│   ├── email_harvest.py            # Email harvesting module
│   ├── tech_fingerprint.py         # Technology fingerprinting module
│   ├── port_scanner.py             # Port scanner module
│   ├── shodan_lookup.py            # Shodan API module
│   └── report_generator.py         # HTML report renderer
├── templates/
│   └── report.html                 # Jinja2 HTML report template
├── wordlists/
│   └── subdomains-top1million-5000.txt   # Downloaded by download_wordlist.py
└── reports/                        # Generated HTML reports (git-ignored)
```

---

## Rate Limiting

Built-in throttling is baked into every module to ensure responsible, non-disruptive operation:

| Module | Default Delay |
|--------|--------------|
| DNS queries | 0.1s between requests |
| HTTP requests | 1.5s between requests |
| API calls | 1.0s between requests |
| Port scan | 0.05s per port |

All delays are configurable in `config.py`.

---

## Disclaimer

> **This tool is provided for educational and authorized security research purposes only.**
>
> The techniques and capabilities demonstrated in this project - including port scanning, subdomain enumeration, and email harvesting - are standard methods used by professional penetration testers and security researchers with **explicit written authorization** from the system owner.
>
> **Do not use this tool against systems you do not own or have explicit written permission to test.** Unauthorized reconnaissance may violate:
> - **Computer Fraud and Abuse Act (CFAA)** - United States
> - **Computer Misuse Act 1990** - United Kingdom
> - **Cybercrime laws** in your jurisdiction
>
> The author assumes no liability for misuse of this software. By using this tool, you confirm that you are operating within the bounds of the law and with proper authorization.

---

## License

MIT License - see [LICENSE](LICENSE) for details.
