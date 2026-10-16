"""
Real functional tests for bypass.py.

We can't test ssdp_probe() end-to-end (no real multicast-capable
network here) or verify gateway_relay_check() against a real router
(that part is inherently hardware-dependent - see its own docstring).
But two things ARE testable without either:

1. _collect_replies() - the receive-until-timeout loop both multicast
   paths rely on - only needs a UDP socket and a peer sending it
   datagrams, which loopback can do just fine.

2. gateway_relay_check()'s decision logic - the "no gateway reply ->
   False", "no target reply -> False", "non-TCP reply -> False",
   "TCP but not SYN-ACK -> False", "SYN-ACK -> True" branching - is
   plain Python wrapped around three scapy calls (srp, srp1, and the
   TCP flags check). With scapy.all stubbed (tests/_fake_scapy.py) so
   the module imports, we can patch srp/srp1's return values and
   drive every branch of that logic for real.
"""

import socket
import threading
import time
import unittest
from unittest.mock import patch

from scandy.bypass import _collect_replies, gateway_relay_check


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


class FakeArpReply:
    """Stands in for the scapy packet srp() returns when resolving the
    gateway's MAC - gateway_relay_check() only reads .hwsrc."""
    def __init__(self, hwsrc):
        self.hwsrc = hwsrc


class FakeTcpReply:
    """
    Stands in for the scapy packet srp1() returns for the relay probe.
    gateway_relay_check() calls reply.haslayer(TCP) and reply[TCP].flags -
    this fakes both regardless of which layer class is passed in, since
    these tests only ever ask about TCP.
    """
    def __init__(self, has_tcp: bool, flags: int):
        self._has_tcp = has_tcp
        self._flags = flags

    def haslayer(self, layer):
        return self._has_tcp

    def __getitem__(self, layer):
        return self

    @property
    def flags(self):
        return self._flags


class TestGatewayRelayCheck(unittest.TestCase):
    """
    gateway_relay_check()'s own docstring is honest that its real
    behavior can only be verified against a real router - these tests
    don't contradict that. What they verify instead is the decision
    logic WRAPPED AROUND the two scapy calls: given each possible shape
    of reply scapy could hand back, does the function return the right
    True/False and does it avoid calling srp1() when there's no point
    (no gateway reply at all)?
    """

    def test_no_gateway_reply_returns_false_without_probing_target(self):
        with patch("scapy.all.srp", return_value=([], [])), \
             patch("scapy.all.srp1") as mock_srp1:
            result = gateway_relay_check("192.168.1.1", "192.168.1.50")

        self.assertFalse(result)
        # No point sending the relay probe if we can't even reach the
        # gateway - this also guards against wasting the full timeout
        # twice in a row for no reason.
        mock_srp1.assert_not_called()

    def test_gateway_reachable_but_target_never_replies(self):
        fake_arp_answered = [("sent", FakeArpReply(hwsrc="aa:bb:cc:dd:ee:ff"))]
        with patch("scapy.all.srp", return_value=(fake_arp_answered, [])), \
             patch("scapy.all.srp1", return_value=None):
            result = gateway_relay_check("192.168.1.1", "192.168.1.50")

        self.assertFalse(result)

    def test_reply_with_no_tcp_layer_is_not_treated_as_success(self):
        fake_arp_answered = [("sent", FakeArpReply(hwsrc="aa:bb:cc:dd:ee:ff"))]
        fake_reply = FakeTcpReply(has_tcp=False, flags=0)
        with patch("scapy.all.srp", return_value=(fake_arp_answered, [])), \
             patch("scapy.all.srp1", return_value=fake_reply):
            result = gateway_relay_check("192.168.1.1", "192.168.1.50")

        self.assertFalse(result)

    def test_tcp_reply_without_syn_ack_flags_is_not_success(self):
        fake_arp_answered = [("sent", FakeArpReply(hwsrc="aa:bb:cc:dd:ee:ff"))]
        # RST (0x04) - the target actively refused; that's still a real
        # reply, but NOT evidence the gateway relayed a working connection.
        fake_reply = FakeTcpReply(has_tcp=True, flags=0x04)
        with patch("scapy.all.srp", return_value=(fake_arp_answered, [])), \
             patch("scapy.all.srp1", return_value=fake_reply):
            result = gateway_relay_check("192.168.1.1", "192.168.1.50")

        self.assertFalse(result)

    def test_syn_ack_reply_is_reported_as_successful_relay(self):
        fake_arp_answered = [("sent", FakeArpReply(hwsrc="aa:bb:cc:dd:ee:ff"))]
        fake_reply = FakeTcpReply(has_tcp=True, flags=0x12)  # SYN+ACK
        with patch("scapy.all.srp", return_value=(fake_arp_answered, [])), \
             patch("scapy.all.srp1", return_value=fake_reply):
            result = gateway_relay_check("192.168.1.1", "192.168.1.50")

        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
