"""
Shared scapy stub for the test suite.

This sandbox has no path to install real scapy (pip and apt are both
policy-blocked here). Rather than skip every test that touches
discover.py or bypass.py, this registers a minimal fake scapy.all
(ARP, Ether, IP, TCP, srp, srp1) in sys.modules so `from scapy.all
import ...` succeeds wherever those modules need it. Tests then patch
srp()/srp1()'s return values per-test to exercise the real logic
around them - discover.py's reply parsing, bypass.py's relay-check
decision tree - and by extension anything (cli.py, report.py) that
calls through to those.

Imported from tests/__init__.py so it's installed before any test
module is collected, regardless of alphabetical load order.

This does NOT verify real scapy's ARP/Ether/IP/TCP/srp/srp1 behavior
- only that netrecon/scandy's own code does the right thing with
whatever scapy gives it. Real packet behavior needs real scapy on
real hardware.
"""

import sys
import types


def install():
    if "scapy.all" in sys.modules:
        return  # already installed (e.g. re-imported across test modules)

    class FakeLayer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.layers = [self]

        def __truediv__(self, other):
            # Mimic scapy's packet-stacking operator. Must return
            # something that ALSO supports / , since real code chains
            # more than two layers (Ether() / IP() / TCP()) - returning
            # a plain tuple here breaks on the second "/".
            stacked = FakeLayer()
            stacked.layers = self.layers + other.layers
            return stacked

    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    fake_scapy_all.ARP = FakeLayer
    fake_scapy_all.Ether = FakeLayer
    fake_scapy_all.IP = FakeLayer
    fake_scapy_all.TCP = FakeLayer
    fake_scapy_all.srp = lambda *a, **kw: ([], [])
    fake_scapy_all.srp1 = lambda *a, **kw: None
    fake_scapy.all = fake_scapy_all

    sys.modules["scapy"] = fake_scapy
    sys.modules["scapy.all"] = fake_scapy_all


install()
