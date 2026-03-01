"""
Port Scanner Module
Scans ports 1-1024 on a target IP/hostname using threaded sockets.
Attempts basic banner grabbing on open ports.

Usage (standalone):
    python -m modules.port_scanner example.com
"""

import sys
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from .models import PortScanResult, OpenPort
import config

# Well-known port → service name
COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class PortScanner:
    def _grab_banner(self, host: str, port: int) -> str | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            try:
                sock.connect((host, port))
                if port in (80, 8080, 8000, 8008):
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                return banner[:120] if banner else None
            finally:
                sock.close()
        except Exception:
            return None

    def _scan_port(self, host: str, port: int) -> tuple[int, bool]:
        try:
            time.sleep(config.RATE_LIMIT_PORT_SCAN)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.PORT_SCAN_TIMEOUT)
            try:
                result = sock.connect_ex((host, port))
                return port, result == 0
            finally:
                sock.close()
        except Exception:
            return port, False

    def run(self, target: str, port_range: tuple[int, int] = (1, 1024)) -> PortScanResult:
        result = PortScanResult(
            target=target,
            scanned_range=f"{port_range[0]}-{port_range[1]}",
        )
        # Resolve hostname to IP
        try:
            host = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.error = f"Cannot resolve {target}: {e}"
            return result

        ports = list(range(port_range[0], port_range[1] + 1))
        print(f"[*] Scanning {len(ports)} ports on {target} ({host})...")

        open_ports: list[OpenPort] = []
        with ThreadPoolExecutor(max_workers=config.PORT_SCAN_THREADS) as executor:
            futures = {executor.submit(self._scan_port, host, p): p for p in ports}
            with tqdm(total=len(futures), desc="Port scan", unit="port") as bar:
                for future in as_completed(futures):
                    port, is_open = future.result()
                    bar.update(1)
                    if is_open:
                        service = COMMON_SERVICES.get(port, "")
                        banner = self._grab_banner(host, port)
                        label = f"{service} | {banner}" if banner else service
                        open_ports.append(OpenPort(port=port, banner=label or None))

        result.open_ports = sorted(open_ports, key=lambda p: p.port)
        return result


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    res = PortScanner().run(target)
    print(f"\nOpen ports on {res.target}:")
    for p in res.open_ports:
        print(f"  {p.port:5d}  {p.banner or ''}")
    if res.error:
        print(f"Error: {res.error}")
