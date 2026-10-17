"""
Real functional test for report.py's render() logic.

run_full_scan() can't be tested here (needs scapy + a real LAN), but
render() is pure formatting over data we can construct by hand - so
we build a fake NetworkReport with known inputs and check the output
actually contains what it should, instead of just checking it doesn't
crash.
"""

import json
import os
import unittest
from unittest.mock import patch

from scandy import colors
from scandy.models import Host
from scandy.portscan import ScanResult
from scandy.isolation import IsolationReport
from scandy.report import NetworkReport


class TestReport(unittest.TestCase):
    def test_render_includes_all_sections(self):
        host1 = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        host2 = Host(ip="192.168.1.50", mac="11:22:33:44:55:66")

        port_results = [
            ScanResult(host=host1, open_ports={80: "HTTP", 443: "HTTPS"}),
            ScanResult(host=host2, open_ports={}),
        ]
        isolation_results = [
            IsolationReport(host=host1, arp_reachable=True, tcp_reachable=True, likely_isolated=False),
            IsolationReport(host=host2, arp_reachable=True, tcp_reachable=False, likely_isolated=True),
        ]

        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host1, host2],
            port_results=port_results,
            isolation_results=isolation_results,
        )

        text = report.render()

        # Subnet and host count show up
        self.assertIn("192.168.1.0/24", text)
        self.assertIn("Hosts found: 2", text)

        # Both hosts and their details appear somewhere in the report
        self.assertIn("192.168.1.1", text)
        self.assertIn("192.168.1.50", text)
        self.assertIn("80/HTTP", text)
        self.assertIn("no open ports found", text)

        # Isolation verdict line is present and reflects mixed results
        self.assertIn("Mixed results", text)

    def test_render_handles_empty_report(self):
        report = NetworkReport(subnet="10.0.0.0/24")
        text = report.render()

        self.assertIn("Hosts found: 0", text)
        self.assertIn("No hosts to evaluate.", text)

    def test_to_json_round_trips_and_is_valid_json(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(host=host, open_ports={80: "HTTP"})],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=True, likely_isolated=False)
            ],
        )

        raw = report.to_json()
        # json.loads will raise if this isn't actually valid JSON -
        # that's the real test, not just "a string came back".
        parsed = json.loads(raw)

        self.assertEqual(parsed["subnet"], "192.168.1.0/24")
        self.assertEqual(parsed["hosts"], [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}])
        self.assertEqual(parsed["port_results"][0]["open_ports"], {"80": "HTTP"})
        self.assertEqual(parsed["isolation_results"][0]["likely_isolated"], False)
        self.assertIn("isolation_verdict", parsed)

    def test_render_includes_banner_section_when_banners_present(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(
                host=host,
                open_ports={22: "SSH"},
                banners={22: "SSH-2.0-OpenSSH_7.4"},
            )],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=True, likely_isolated=False)
            ],
        )
        text = report.render()

        self.assertIn("Service banners:", text)
        self.assertIn("SSH-2.0-OpenSSH_7.4", text)

    def test_render_omits_banner_section_when_no_banners(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(host=host, open_ports={22: "SSH"})],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=True, likely_isolated=False)
            ],
        )
        text = report.render()

        self.assertNotIn("Service banners:", text)

    def test_to_dict_includes_banners(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(
                host=host,
                open_ports={22: "SSH"},
                banners={22: "SSH-2.0-OpenSSH_7.4"},
            )],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=True, likely_isolated=False)
            ],
        )
        parsed = json.loads(report.to_json())

        self.assertEqual(parsed["port_results"][0]["banners"], {"22": "SSH-2.0-OpenSSH_7.4"})

    def test_render_default_has_no_ansi_codes(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(host=host, open_ports={80: "HTTP"})],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=False, likely_isolated=True)
            ],
        )
        # Even if we're in an environment where color WOULD be enabled,
        # render() with no args must stay plain - this is the text that
        # can get written straight to a file.
        with patch.object(colors.sys.stdout, "isatty", return_value=True):
            os.environ.pop("NO_COLOR", None)
            text = report.render()
        self.assertNotIn("\033[", text)

    def test_render_color_true_adds_ansi_codes_on_a_tty(self):
        host = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        report = NetworkReport(
            subnet="192.168.1.0/24",
            hosts=[host],
            port_results=[ScanResult(host=host, open_ports={80: "HTTP"})],
            isolation_results=[
                IsolationReport(host=host, arp_reachable=True, tcp_reachable=False, likely_isolated=True)
            ],
        )
        with patch.object(colors.sys.stdout, "isatty", return_value=True):
            os.environ.pop("NO_COLOR", None)
            text = report.render(color=True)
        self.assertIn("\033[", text)
        # The isolated host's verdict should specifically be red.
        self.assertIn(colors.RED, text)


if __name__ == "__main__":
    unittest.main()
