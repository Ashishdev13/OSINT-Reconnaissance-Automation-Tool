"""
Subdomain Brute-Force Module
Resolves subdomains from a wordlist using threaded DNS lookups.

Wordlist: wordlists/subdomains-top1million-5000.txt (SecLists)

Usage (standalone):
    python -m modules.subdomain_bruteforce example.com
"""

import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from .models import SubdomainResult, Subdomain
import config


class SubdomainBruteforce:
    def _resolve(self, fqdn: str) -> tuple[str, str | None]:
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except socket.gaierror:
            return fqdn, None

    def _load_wordlist(self) -> list[str]:
        try:
            with open(config.WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Wordlist not found at {config.WORDLIST_PATH}")
            print("    Run: python download_wordlist.py")
            return []

    def run(self, domain: str) -> SubdomainResult:
        result = SubdomainResult(domain=domain)
        words = self._load_wordlist()
        if not words:
            result.error = "Wordlist not found"
            return result

        result.total_checked = len(words)
        fqdns = [f"{w}.{domain}" for w in words]

        print(f"[*] Brute-forcing {len(fqdns)} subdomains for {domain}...")
        found: list[Subdomain] = []

        with ThreadPoolExecutor(max_workers=config.SUBDOMAIN_THREADS) as executor:
            futures = {executor.submit(self._resolve, fqdn): fqdn for fqdn in fqdns}
            with tqdm(total=len(futures), desc="Subdomains", unit="sub") as bar:
                for future in as_completed(futures):
                    fqdn, ip = future.result()
                    bar.update(1)
                    if ip:
                        name = fqdn.replace(f".{domain}", "")
                        found.append(Subdomain(name=name, ip=ip))

        result.subdomains = sorted(found, key=lambda s: s.name)
        return result


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = SubdomainBruteforce().run(domain)
    print(f"\nFound {len(res.subdomains)} subdomains:")
    for s in res.subdomains:
        print(f"  {s.name}.{domain} -> {s.ip}")
    if res.error:
        print(f"Error: {res.error}")
