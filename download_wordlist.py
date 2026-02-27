#!/usr/bin/env python3
"""
Downloads the SecLists subdomains-top1million-5000.txt wordlist
into the wordlists/ directory.
"""

import os
import sys
import urllib.request

WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Discovery/DNS/subdomains-top1million-5000.txt"
)

DEST = os.path.join(os.path.dirname(__file__), "wordlists", "subdomains-top1million-5000.txt")


def main() -> None:
    os.makedirs(os.path.dirname(DEST), exist_ok=True)

    if os.path.exists(DEST):
        size = os.path.getsize(DEST)
        print(f"[+] Wordlist already exists ({size:,} bytes): {DEST}")
        return

    print(f"[*] Downloading SecLists wordlist from GitHub...")
    try:
        urllib.request.urlretrieve(WORDLIST_URL, DEST)
        size = os.path.getsize(DEST)
        with open(DEST) as f:
            lines = sum(1 for _ in f)
        print(f"[+] Saved {lines:,} subdomains ({size:,} bytes) → {DEST}")
    except Exception as e:
        print(f"[-] Download failed: {e}")
        print(f"    Manually download from:\n    {WORDLIST_URL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
