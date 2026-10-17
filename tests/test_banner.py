"""
Real functional tests for banner.py - actual sockets, actual TLS
(a throwaway self-signed cert generated at test time), no mocking of
network behavior. The only thing mocked is grab_banner()'s port-based
dispatch logic, since that's pure branching with nothing to connect
to.
"""

import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scandy.banner import _probe_http, _read_passive_banner, grab_banner, grab_banners


def _free_port() -> int:
    """Ask the OS for a free loopback port instead of hardcoding one,
    so these tests don't collide with anything else running."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestGrabBannerDispatch(unittest.TestCase):
    """grab_banner()'s job is just picking the right strategy per port -
    tested by mocking the two strategies and checking which one (and
    with what use_tls value) gets called for each port category."""

    def test_https_ports_use_tls_probe(self):
        for port in (443, 8443):
            with self.subTest(port=port):
                with patch("scandy.banner._probe_http", return_value="banner") as mock_probe:
                    grab_banner("127.0.0.1", port)
                mock_probe.assert_called_once()
                _, kwargs_or_args = mock_probe.call_args, mock_probe.call_args.args
                self.assertTrue(mock_probe.call_args.args[-1] is True or
                                 mock_probe.call_args.kwargs.get("use_tls") is True)

    def test_http_ports_use_plain_probe(self):
        for port in (80, 8080, 5000):
            with self.subTest(port=port):
                with patch("scandy.banner._probe_http", return_value="banner") as mock_probe:
                    grab_banner("127.0.0.1", port)
                mock_probe.assert_called_once()
                self.assertTrue(mock_probe.call_args.args[-1] is False or
                                 mock_probe.call_args.kwargs.get("use_tls") is False)

    def test_other_ports_use_passive_read(self):
        for port in (22, 21, 25, 9999):
            with self.subTest(port=port):
                with patch("scandy.banner._read_passive_banner", return_value="banner") as mock_read, \
                     patch("scandy.banner._probe_http") as mock_probe:
                    grab_banner("127.0.0.1", port)
                mock_read.assert_called_once()
                mock_probe.assert_not_called()


class TestReadPassiveBanner(unittest.TestCase):
    def test_grabs_greeting_sent_immediately_on_connect(self):
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)

        def serve_one():
            conn, _ = listener.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
            time.sleep(0.2)
            conn.close()

        threading.Thread(target=serve_one, daemon=True).start()
        time.sleep(0.05)

        banner = _read_passive_banner("127.0.0.1", port, timeout=2.0)
        listener.close()

        self.assertEqual(banner, "SSH-2.0-OpenSSH_7.4")

    def test_returns_none_when_server_sends_nothing(self):
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)

        def serve_one_silently():
            conn, _ = listener.accept()
            time.sleep(1.0)  # accept but never send anything
            conn.close()

        threading.Thread(target=serve_one_silently, daemon=True).start()
        time.sleep(0.05)

        start = time.time()
        banner = _read_passive_banner("127.0.0.1", port, timeout=0.3)
        elapsed = time.time() - start
        listener.close()

        self.assertIsNone(banner)
        # Confirms it actually waited ~timeout rather than hanging or
        # returning instantly - both would indicate a broken timeout.
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 1.0)

    def test_returns_none_when_nothing_is_listening(self):
        port = _free_port()  # free precisely because nothing is bound to it
        banner = _read_passive_banner("127.0.0.1", port, timeout=0.5)
        self.assertIsNone(banner)


class TestProbeHttp(unittest.TestCase):
    def test_sends_head_request_and_reads_server_header(self):
        port = _free_port()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        received_request = {}

        def serve_one():
            conn, _ = listener.accept()
            conn.settimeout(2.0)
            received_request["data"] = conn.recv(4096).decode(errors="replace")
            conn.sendall(b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: 0\r\n\r\n")
            conn.close()

        threading.Thread(target=serve_one, daemon=True).start()
        time.sleep(0.05)

        banner = _probe_http("127.0.0.1", port, timeout=2.0, use_tls=False)
        listener.close()

        # We actually sent a real HTTP request...
        self.assertIn("HEAD / HTTP/1.1", received_request["data"])
        self.assertIn("Host: 127.0.0.1", received_request["data"])
        # ...and got the real response back, Server header included.
        self.assertIn("Server: TestServer/1.0", banner)

    def test_returns_none_on_connection_refused(self):
        port = _free_port()
        banner = _probe_http("127.0.0.1", port, timeout=0.5, use_tls=False)
        self.assertIsNone(banner)


class TestProbeHttpsWithRealTls(unittest.TestCase):
    """
    Generates a real, throwaway self-signed certificate with openssl
    and runs a real TLS handshake against it - this is the one part of
    banner.py that's easy to get subtly wrong (cert verification left
    on by accident would make every real-world self-signed-cert HTTPS
    service silently return None instead of a banner), so it's worth
    testing for real rather than trusting the code by inspection.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.cert_path = str(Path(cls.tmpdir) / "cert.pem")
        cls.key_path = str(Path(cls.tmpdir) / "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", cls.key_path, "-out", cls.cert_path,
                "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
            ],
            check=True, capture_output=True,
        )

    def test_https_probe_completes_tls_handshake_against_self_signed_cert(self):
        port = _free_port()
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert_path, self.key_path)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)

        def serve_one_tls():
            raw_conn, _ = listener.accept()
            tls_conn = server_context.wrap_socket(raw_conn, server_side=True)
            tls_conn.settimeout(2.0)
            tls_conn.recv(4096)
            tls_conn.sendall(b"HTTP/1.1 200 OK\r\nServer: SecureTestServer/2.0\r\n\r\n")
            tls_conn.close()

        threading.Thread(target=serve_one_tls, daemon=True).start()
        time.sleep(0.1)

        banner = _probe_http("127.0.0.1", port, timeout=2.0, use_tls=True)
        listener.close()

        # This only passes if _probe_http actually completed a real TLS
        # handshake against a cert it has no reason to trust by default -
        # proving certificate verification really is disabled, not just
        # claimed in the docstring.
        self.assertIsNotNone(banner)
        self.assertIn("SecureTestServer/2.0", banner)


if __name__ == "__main__":
    unittest.main()
