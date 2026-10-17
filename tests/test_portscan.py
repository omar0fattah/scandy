"""
Real functional test for portscan.py - no mocking. We spin up actual
TCP listeners on loopback (127.0.0.1) and confirm scan_host finds them
open, and finds nearby closed ports closed. This is the kind of test
that actually proves the socket logic works, not just that it parses.
"""

import socket
import threading
import unittest

from scandy.models import Host
from scandy.portscan import scan_host


def start_listener(port: int):
    """Start a bare-bones TCP listener on 127.0.0.1:port in a thread."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                break  # socket was closed, exit thread

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    return srv


def start_greeting_listener(port: int, greeting: bytes):
    """Like start_listener, but sends a greeting immediately on connect -
    for testing that scan_host's banner grab actually captures it."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
                conn.sendall(greeting)
                conn.close()
            except OSError:
                break

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    return srv


class TestPortScan(unittest.TestCase):
    def test_finds_open_port_and_skips_closed_one(self):
        # Use high, unassigned ports so we don't collide with real services.
        open_port = 54321
        closed_port = 54322  # deliberately never bound

        listener = start_listener(open_port)
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            test_ports = {open_port: "test-open", closed_port: "test-closed"}

            result = scan_host(host, ports=test_ports, timeout=0.3)

            self.assertIn(open_port, result.open_ports)
            self.assertNotIn(closed_port, result.open_ports)
        finally:
            listener.close()


class TestPortScanBanners(unittest.TestCase):
    """
    scan_host() is supposed to grab a banner from each open port it
    finds (banner.py handles the actual grabbing logic and has its own
    dedicated tests - this just confirms scan_host wires the two
    together correctly: open ports get banners attempted, closed ports
    don't, and grab_banners=False skips the step entirely).
    """

    def test_open_port_banner_is_captured(self):
        port = 54323
        listener = start_greeting_listener(port, b"TEST-BANNER-1.0\r\n")
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            result = scan_host(host, ports={port: "test-svc"}, timeout=0.5)

            self.assertIn(port, result.open_ports)
            self.assertEqual(result.banners.get(port), "TEST-BANNER-1.0")
        finally:
            listener.close()

    def test_closed_port_has_no_banner_entry(self):
        closed_port = 54324  # never bound
        host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
        result = scan_host(host, ports={closed_port: "test-svc"}, timeout=0.3)

        self.assertNotIn(closed_port, result.open_ports)
        self.assertNotIn(closed_port, result.banners)

    def test_grab_banners_false_skips_banner_grabbing(self):
        port = 54325
        listener = start_greeting_listener(port, b"SHOULD-NOT-BE-CAPTURED\r\n")
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            result = scan_host(host, ports={port: "test-svc"}, timeout=0.5, grab_banners=False)

            self.assertIn(port, result.open_ports)
            self.assertEqual(result.banners, {})
        finally:
            listener.close()

    def test_str_includes_banner_when_present(self):
        port = 54326
        listener = start_greeting_listener(port, b"SOME-SERVICE/2.1\r\n")
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            result = scan_host(host, ports={port: "test-svc"}, timeout=0.5)
            text = str(result)

            self.assertIn("SOME-SERVICE/2.1", text)
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
