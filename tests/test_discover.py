"""
Real functional test for discover.py's parsing/sorting logic.

discover.py needs scapy for the actual ARP packet send/receive (ARP,
Ether, srp), and this sandbox has no path to install scapy (pip and
apt are both policy-blocked here - not a bug, just an environment
boundary). So instead of skipping this module entirely, tests/
__init__.py installs a fake scapy.all (see tests/_fake_scapy.py)
before any test module is collected, so `from scapy.all import ARP,
Ether, srp` succeeds. We then patch srp()'s return value per-test and
let scan()'s own logic run for real: building the request, calling
srp(), and - the part most likely to actually have a bug - turning
(sent, received) pairs into sorted Host objects.

This proves scan()'s logic is correct. It does NOT prove scapy's
real ARP/Ether/srp behave the way we assume - that part can only be
verified on real hardware with real scapy installed, which the
project's README already says.
"""

import unittest
from unittest.mock import patch

from scandy import discover


class FakeReceived:
    """Stands in for the scapy packet srp() returns as the reply half
    of each (sent, received) pair - scan() only reads .psrc/.hwsrc."""
    def __init__(self, psrc, hwsrc):
        self.psrc = psrc
        self.hwsrc = hwsrc


class TestDiscoverScan(unittest.TestCase):
    def test_builds_host_list_from_srp_replies(self):
        fake_answered = [
            ("sent1", FakeReceived(psrc="192.168.1.50", hwsrc="aa:aa:aa:aa:aa:aa")),
            ("sent2", FakeReceived(psrc="192.168.1.5", hwsrc="bb:bb:bb:bb:bb:bb")),
            ("sent3", FakeReceived(psrc="192.168.1.100", hwsrc="cc:cc:cc:cc:cc:cc")),
        ]
        with patch.object(discover, "srp", return_value=(fake_answered, [])) as mock_srp:
            hosts = discover.scan("192.168.1.0/24", timeout=5)

        # srp() must actually be called with the timeout we passed through.
        _, kwargs = mock_srp.call_args
        self.assertEqual(kwargs.get("timeout"), 5)

        # Three replies in should mean three Host objects out, correctly
        # pulling ip from psrc and mac from hwsrc.
        self.assertEqual(len(hosts), 3)
        self.assertEqual(hosts[0].ip, "192.168.1.5")   # sorted numerically...
        self.assertEqual(hosts[1].ip, "192.168.1.50")  # ...not as strings
        self.assertEqual(hosts[2].ip, "192.168.1.100")
        self.assertEqual(hosts[1].mac, "aa:aa:aa:aa:aa:aa")

    def test_no_replies_returns_empty_list(self):
        with patch.object(discover, "srp", return_value=([], [])):
            hosts = discover.scan("10.0.0.0/24")
        self.assertEqual(hosts, [])

    def test_sorts_numerically_not_lexically(self):
        # This is the bug this test exists to catch: string-sorting IPs
        # puts "192.168.1.100" before "192.168.1.50" (since "1" < "5"
        # character-by-character), which is wrong. discover.scan()
        # explicitly sorts by int-tuple to avoid this.
        fake_answered = [
            ("s", FakeReceived(psrc="192.168.1.9", hwsrc="00:00:00:00:00:01")),
            ("s", FakeReceived(psrc="192.168.1.100", hwsrc="00:00:00:00:00:02")),
            ("s", FakeReceived(psrc="192.168.1.11", hwsrc="00:00:00:00:00:03")),
        ]
        with patch.object(discover, "srp", return_value=(fake_answered, [])):
            hosts = discover.scan("192.168.1.0/24")

        self.assertEqual([h.ip for h in hosts], ["192.168.1.9", "192.168.1.11", "192.168.1.100"])


if __name__ == "__main__":
    unittest.main()
