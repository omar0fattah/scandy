"""
Real functional tests for isolation.py. We simulate the two cases
that matter:

  1. A "reachable" host - something is listening, so check_host should
     report tcp_reachable=True and likely_isolated=False.
  2. An "isolated-looking" host - nothing listens on any common port,
     so check_host should report tcp_reachable=False and
     likely_isolated=True.

We can't simulate real client isolation in this sandbox (that's a
property of actual Wi-Fi hardware), but we CAN prove the detection
*logic* behaves correctly given each kind of input, using real sockets
on loopback rather than mocked ones.
"""

import socket
import threading
import unittest

from scandy.models import Host
from scandy.isolation import check_host


def start_listener(port: int):
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
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv


class TestIsolation(unittest.TestCase):
    def test_reachable_host_is_not_flagged_isolated(self):
        # Temporarily point COMMON_PORTS-like behavior at a port we control
        # by monkeypatching the module's port list for this test only.
        import scandy.isolation as isolation_mod

        test_port = 54400
        listener = start_listener(test_port)
        original_ports = isolation_mod.COMMON_PORTS
        isolation_mod.COMMON_PORTS = {test_port: "test"}
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            report = check_host(host, timeout=0.3)
            self.assertTrue(report.tcp_reachable)
            self.assertFalse(report.likely_isolated)
        finally:
            isolation_mod.COMMON_PORTS = original_ports
            listener.close()

    def test_unreachable_host_is_flagged_isolated(self):
        import scandy.isolation as isolation_mod

        # Ports nothing is listening on.
        original_ports = isolation_mod.COMMON_PORTS
        isolation_mod.COMMON_PORTS = {54401: "test", 54402: "test2"}
        try:
            host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")
            report = check_host(host, timeout=0.3)
            self.assertFalse(report.tcp_reachable)
            self.assertTrue(report.likely_isolated)
        finally:
            isolation_mod.COMMON_PORTS = original_ports


if __name__ == "__main__":
    unittest.main()
