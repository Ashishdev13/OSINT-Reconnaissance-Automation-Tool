"""Tests for port_scanner.py — socket cleanup, banner grabbing, scan logic."""

import socket
import pytest
from unittest.mock import patch, MagicMock, call
from modules.port_scanner import PortScanner, COMMON_SERVICES
from modules.models import PortScanResult


class TestScanPort:
    """Tests for _scan_port method."""

    @patch("modules.port_scanner.socket.socket")
    def test_open_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        port, is_open = scanner._scan_port("127.0.0.1", 80)

        assert port == 80
        assert is_open is True
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_closed_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        port, is_open = scanner._scan_port("127.0.0.1", 9999)

        assert port == 9999
        assert is_open is False
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_socket_closed_on_exception(self, mock_sock_cls):
        """Socket must be closed even when connect_ex raises."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("Connection error")
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        port, is_open = scanner._scan_port("127.0.0.1", 80)

        assert is_open is False
        mock_sock.close.assert_called_once()


class TestGrabBanner:
    """Tests for _grab_banner method."""

    @patch("modules.port_scanner.socket.socket")
    def test_banner_on_web_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx"
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner._grab_banner("127.0.0.1", 80)

        assert banner is not None
        assert "HTTP/1.1" in banner
        mock_sock.send.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_no_send_on_non_web_port(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner._grab_banner("127.0.0.1", 22)

        assert "SSH" in banner
        mock_sock.send.assert_not_called()
        mock_sock.close.assert_called_once()

    @patch("modules.port_scanner.socket.socket")
    def test_banner_truncated_to_120(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"A" * 256
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner._grab_banner("127.0.0.1", 22)

        assert len(banner) == 120

    @patch("modules.port_scanner.socket.socket")
    def test_returns_none_on_empty_banner(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner._grab_banner("127.0.0.1", 22)

        assert banner is None

    @patch("modules.port_scanner.socket.socket")
    def test_socket_closed_on_connect_exception(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_sock_cls.return_value = mock_sock

        scanner = PortScanner()
        banner = scanner._grab_banner("127.0.0.1", 80)

        assert banner is None
        mock_sock.close.assert_called_once()


class TestPortScannerRun:
    """Tests for the run() orchestration method."""

    @patch("modules.port_scanner.socket.gethostbyname")
    def test_unresolvable_target(self, mock_resolve):
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")

        scanner = PortScanner()
        result = scanner.run("nonexistent.invalid")

        assert result.error is not None
        assert "nonexistent.invalid" in result.error
        assert len(result.open_ports) == 0

    @patch("modules.port_scanner.tqdm")
    @patch("modules.port_scanner.socket.gethostbyname", return_value="127.0.0.1")
    @patch("modules.port_scanner.socket.socket")
    def test_scan_finds_open_ports(self, mock_sock_cls, mock_resolve, mock_tqdm):
        mock_sock = MagicMock()
        # Port 80 open, all others closed
        def connect_ex_side_effect(addr):
            return 0 if addr[1] == 80 else 111
        mock_sock.connect_ex.side_effect = connect_ex_side_effect
        mock_sock.recv.return_value = b""
        mock_sock_cls.return_value = mock_sock
        mock_tqdm.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_tqdm.return_value.__exit__ = MagicMock(return_value=False)

        scanner = PortScanner()
        result = scanner.run("example.com", port_range=(79, 81))

        assert result.error is None
        assert any(p.port == 80 for p in result.open_ports)

    def test_common_services_dict(self):
        """Verify well-known services are mapped."""
        assert COMMON_SERVICES[22] == "SSH"
        assert COMMON_SERVICES[80] == "HTTP"
        assert COMMON_SERVICES[443] == "HTTPS"
        assert COMMON_SERVICES[3306] == "MySQL"
