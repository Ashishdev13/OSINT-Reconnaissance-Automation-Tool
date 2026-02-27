#!/usr/bin/env python3
"""
OSINT Reconnaissance Automation Tool
=====================================
Modular reconnaissance framework for authorized security assessments.

Usage:
    python main.py --domain example.com --all
    python main.py --domain example.com --whois --dns --ports
    python main.py --domain example.com --subdomains --emails --tech --shodan

ETHICAL USE DISCLAIMER:
    This tool is intended solely for authorized security testing, penetration
    testing engagements, bug bounty programs, and defensive security research.
    Unauthorized use against systems you do not own or have explicit written
    permission to test may violate computer fraud and abuse laws.
"""

import argparse
import os
import sys
import time
import webbrowser
from colorama import Fore, Style, init

init(autoreset=True)

DISCLAIMER = f"""
{Fore.YELLOW}{'='*70}
  OSINT RECONNAISSANCE AUTOMATION TOOL
  For Authorized Security Research Only
{'='*70}

{Fore.RED}  ⚠  ETHICAL USE DISCLAIMER  ⚠{Style.RESET_ALL}

  This tool is intended solely for:
    • Authorized penetration testing engagements
    • Bug bounty programs where reconnaissance is permitted
    • Defensive security research on systems you own
    • CTF (Capture the Flag) competitions

  Unauthorized use against systems you do not own or have explicit
  written permission to test may violate:
    • Computer Fraud and Abuse Act (CFAA) — United States
    • Computer Misuse Act — United Kingdom
    • Similar cybercrime legislation in your jurisdiction

{Fore.YELLOW}{'='*70}{Style.RESET_ALL}
"""


def print_step(msg: str) -> None:
    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def print_ok(msg: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_err(msg: str) -> None:
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def confirm_disclaimer() -> bool:
    print(DISCLAIMER)
    ans = input(
        f"{Fore.YELLOW}Do you have explicit authorization to perform reconnaissance"
        f" on the target? [yes/NO]: {Style.RESET_ALL}"
    ).strip().lower()
    return ans in ("yes", "y")


def run(args: argparse.Namespace) -> None:
    from modules.models import ReconResult
    from modules.report_generator import ReportGenerator

    domain = args.domain.lower().strip().lstrip("https://").lstrip("http://").rstrip("/")
    recon = ReconResult(domain=domain)

    run_all = args.all

    # ── WHOIS ────────────────────────────────────────────────────────────
    if run_all or args.whois:
        print_step(f"Running WHOIS lookup for {domain}...")
        from modules.whois_lookup import WhoisLookup
        recon.whois = WhoisLookup().run(domain)
        if recon.whois.error:
            print_warn(f"WHOIS: {recon.whois.error}")
        else:
            print_ok(f"Registrar: {recon.whois.registrar or 'N/A'} | Expires: {recon.whois.expiration_date or 'N/A'}")

    # ── DNS ──────────────────────────────────────────────────────────────
    if run_all or args.dns:
        print_step(f"Enumerating DNS records for {domain}...")
        from modules.dns_enum import DNSEnum
        recon.dns = DNSEnum().run(domain)
        if recon.dns.error:
            print_warn(f"DNS: {recon.dns.error}")
        else:
            print_ok(
                f"A: {len(recon.dns.a_records)} | MX: {len(recon.dns.mx_records)} | "
                f"NS: {len(recon.dns.ns_records)} | TXT: {len(recon.dns.txt_records)}"
            )

    # ── Subdomains ───────────────────────────────────────────────────────
    if run_all or args.subdomains:
        print_step(f"Brute-forcing subdomains for {domain}...")
        from modules.subdomain_bruteforce import SubdomainBruteforce
        recon.subdomains = SubdomainBruteforce().run(domain)
        if recon.subdomains.error:
            print_warn(f"Subdomains: {recon.subdomains.error}")
        else:
            print_ok(
                f"Found {len(recon.subdomains.subdomains)} subdomains "
                f"out of {recon.subdomains.total_checked} checked"
            )

    # ── Emails ───────────────────────────────────────────────────────────
    if run_all or args.emails:
        print_step(f"Harvesting emails for {domain}...")
        from modules.email_harvest import EmailHarvest
        recon.emails = EmailHarvest().run(domain)
        if recon.emails.error:
            print_warn(f"Emails: {recon.emails.error}")
        else:
            print_ok(f"Found {len(recon.emails.emails)} email(s) via {recon.emails.source}")

    # ── Technology ───────────────────────────────────────────────────────
    if run_all or args.tech:
        print_step(f"Fingerprinting technologies on {domain}...")
        from modules.tech_fingerprint import TechFingerprint
        recon.tech = TechFingerprint().run(domain)
        if recon.tech.error:
            print_warn(f"Tech: {recon.tech.error}")
        else:
            techs = ", ".join(t.name for t in recon.tech.technologies[:5])
            print_ok(f"Detected {len(recon.tech.technologies)} technologies: {techs}{'...' if len(recon.tech.technologies) > 5 else ''}")

    # ── Port Scan ────────────────────────────────────────────────────────
    if run_all or args.ports:
        target = recon.dns.a_records[0] if (recon.dns and recon.dns.a_records) else domain
        print_step(f"Port scanning {target} (ports 1-1024)...")
        from modules.port_scanner import PortScanner
        recon.port_scan = PortScanner().run(target)
        if recon.port_scan.error:
            print_warn(f"Port scan: {recon.port_scan.error}")
        else:
            ports = ", ".join(str(p.port) for p in recon.port_scan.open_ports[:10])
            print_ok(f"Open ports: {ports or 'None'}")

    # ── Shodan ───────────────────────────────────────────────────────────
    if run_all or args.shodan:
        print_step(f"Querying Shodan for {domain}...")
        ips = recon.dns.a_records if (recon.dns and recon.dns.a_records) else None
        from modules.shodan_lookup import ShodanLookup
        recon.shodan = ShodanLookup().run(domain, ips=ips)
        if recon.shodan.error:
            print_warn(f"Shodan: {recon.shodan.error}")
        else:
            total_vulns = sum(len(h.vulns) for h in recon.shodan.hosts)
            print_ok(f"Shodan: {len(recon.shodan.hosts)} host(s), {total_vulns} CVE(s) found")

    # ── Report ───────────────────────────────────────────────────────────
    print_step("Generating HTML report...")
    report_path = ReportGenerator().generate(recon)
    print_ok(f"Report saved: {report_path}")

    if not args.no_open:
        webbrowser.open(f"file://{os.path.abspath(report_path)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="osint",
        description="OSINT Reconnaissance Automation Tool — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --domain example.com --all
  python main.py --domain example.com --whois --dns --tech
  python main.py --domain example.com --ports --shodan
  python main.py --domain example.com --subdomains --no-open
        """,
    )
    parser.add_argument("--domain", "-d", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--all", "-a", action="store_true", help="Run all modules")
    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Run DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain brute-force")
    parser.add_argument("--emails", action="store_true", help="Run email harvesting")
    parser.add_argument("--tech", action="store_true", help="Run technology fingerprinting")
    parser.add_argument("--ports", action="store_true", help="Run port scan (1-1024)")
    parser.add_argument("--shodan", action="store_true", help="Run Shodan lookup")
    parser.add_argument("--no-open", action="store_true", help="Don't auto-open report in browser")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip disclaimer prompt")

    args = parser.parse_args()

    if not any([args.all, args.whois, args.dns, args.subdomains,
                args.emails, args.tech, args.ports, args.shodan]):
        parser.error("Specify at least one module flag (or --all). Use -h for help.")

    if not args.yes and not confirm_disclaimer():
        print_err("Aborted. This tool requires explicit authorization.")
        sys.exit(1)

    print(f"\n{Fore.CYAN}Target: {Style.BRIGHT}{args.domain}{Style.RESET_ALL}")
    t0 = time.time()
    run(args)
    elapsed = time.time() - t0
    print(f"\n{Fore.GREEN}Done in {elapsed:.1f}s{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
