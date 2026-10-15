"""
Real functional tests for cli.py.

We run the actual CLI as a subprocess (not calling main() in-process)
specifically to prove the --help paths work in a clean environment
without importing scapy - that's the whole point of keeping imports
lazy inside each subcommand branch. A subprocess is the only way to
honestly test "does this fail if scapy isn't importable", since an
in-process call would share whatever's already imported in the test
runner.

For portscan/isolation dispatch logic (the parts that don't need
scapy once a host list exists), we test main() in-process against a
fake discover module, which proves the CLI wires config/timeout
through correctly without needing a real network.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from scandy.cli import main
from scandy.models import Host

try:
    import scapy  # noqa: F401
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class TestCliHelpSubprocess(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "scandy", *args],
            cwd="/home/claude/scandy",
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_top_level_help_works_without_scapy(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("discover", result.stdout)
        self.assertIn("portscan", result.stdout)
        self.assertIn("isolation", result.stdout)
        self.assertIn("scan", result.stdout)

    def test_subcommand_help_works_without_scapy(self):
        result = self._run("scan", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--json", result.stdout)
        self.assertIn("--output", result.stdout)

    def test_missing_subcommand_is_a_usage_error(self):
        result = self._run()
        self.assertNotEqual(result.returncode, 0)

    def test_missing_subnet_argument_is_a_usage_error(self):
        result = self._run("discover")
        self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(
    HAS_SCAPY,
    "scandy.discover imports scapy at module level, so patching "
    "scandy.discover.scan requires scapy to be importable even "
    "though these tests never touch real packets. Run these on a "
    "machine with scapy installed (pip install -r requirements.txt).",
)
class TestCliDispatch(unittest.TestCase):
    """
    Tests the parts of main() that don't need scapy - portscan and
    isolation both call discover_scan() internally, so we patch that
    one function out with a fake host list and let everything else
    (config loading, real TCP checks, real report formatting) run for
    real.
    """

    def test_portscan_command_uses_config_ports(self):
        fake_host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")

        config_data = {"ports": {"54500": "test-port"}, "port_timeout": 0.2}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        with patch("scandy.discover.scan", return_value=[fake_host]):
            with patch("sys.stdout", new_callable=StringIO) as fake_out:
                exit_code = main(["portscan", "192.168.1.0/24", "-c", config_path])

        self.assertEqual(exit_code, 0)
        output = fake_out.getvalue()
        # Nothing is listening on 54500, so it should report no open ports -
        # but critically, it should have USED our custom port, not the
        # built-in COMMON_PORTS list (proving config actually wired through).
        self.assertIn("127.0.0.1", output)
        self.assertIn("no open ports found", output)

    def test_isolation_command_runs_and_prints_verdict(self):
        fake_host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")

        with patch("scandy.discover.scan", return_value=[fake_host]):
            with patch("sys.stdout", new_callable=StringIO) as fake_out:
                exit_code = main(["isolation", "192.168.1.0/24", "-t", "0.2"])

        self.assertEqual(exit_code, 0)
        output = fake_out.getvalue()
        self.assertIn("127.0.0.1", output)
        self.assertTrue("Verdict" in output or "ISOLATED" in output or "reachable" in output)


if __name__ == "__main__":
    unittest.main()
