"""
Real functional test for the testable half of bypass.py.

We can't test ssdp_probe() end-to-end (no real multicast-capable
network here), and we can't test gateway_relay_check() at all (needs
scapy + a real router). But _collect_replies() - the receive-until-
timeout loop that both would rely on - only needs a UDP socket and a
peer sending it datagrams, which loopback can do just fine. This
proves the loop actually terminates correctly and collects the right
source IPs, which is where a bug would most likely hide.
"""

import socket
import threading
import time
import unittest

from netrecon.bypass import _collect_replies


class TestCollectReplies(unittest.TestCase):
    def test_collects_replies_from_loopback_sender(self):
        # The "listener" - stands in for the probe socket in ssdp_probe().
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))  # let the OS pick a free port
        listener_port = listener.getsockname()[1]

        # A separate thread plays the role of "a device answering the probe" -
        # sends one datagram shortly after the listener starts collecting.
        def fake_responder():
            time.sleep(0.1)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(b"fake SSDP reply", ("127.0.0.1", listener_port))
            sender.close()

        threading.Thread(target=fake_responder, daemon=True).start()

        replies = _collect_replies(listener, timeout=1.0)
        listener.close()

        self.assertEqual(replies, ["127.0.0.1"])

    def test_returns_empty_list_when_nobody_replies(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))

        start = time.time()
        replies = _collect_replies(listener, timeout=0.3)
        elapsed = time.time() - start
        listener.close()

        self.assertEqual(replies, [])
        # Also confirm it actually waited ~timeout and didn't return instantly
        # or hang - both would indicate a broken deadline calculation.
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertLess(elapsed, 1.0)

    def test_deduplicates_multiple_replies_from_same_ip(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener_port = listener.getsockname()[1]

        def fake_responder():
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(3):
                sender.sendto(b"ping", ("127.0.0.1", listener_port))
                time.sleep(0.05)
            sender.close()

        threading.Thread(target=fake_responder, daemon=True).start()

        replies = _collect_replies(listener, timeout=1.0)
        listener.close()

        # Same IP sent 3 datagrams - should still only appear once.
        self.assertEqual(replies, ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
