"""
Real functional test for portscan.py - no mocking. We spin up actual
TCP listeners on loopback (127.0.0.1) and confirm scan_host finds them
open, and finds nearby closed ports closed. This is the kind of test
that actually proves the socket logic works, not just that it parses.
"""

import socket
import threading
import unittest

from netrecon.models import Host
from netrecon.portscan import scan_host


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


if __name__ == "__main__":
    unittest.main()
