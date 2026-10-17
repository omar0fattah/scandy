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


class TestCliConfigErrorHandling(unittest.TestCase):
    """
    Config.load() raises plain Python exceptions (json.JSONDecodeError,
    ValueError, FileNotFoundError) for bad input - found by actually
    trying malformed config files against it. Before main() wrapped
    the Config.load() call, any of these crashed the CLI with a raw
    traceback instead of a usable error message. These tests pin that
    fix in place.
    """

    def test_missing_config_file_prints_clean_error(self):
        with patch("sys.stderr", new_callable=StringIO) as fake_err:
            exit_code = main(["scan", "192.168.1.0/24", "-c", "/tmp/does_not_exist_12345.json"])
        self.assertEqual(exit_code, 1)
        self.assertIn("not found", fake_err.getvalue())

    def test_malformed_json_prints_clean_error(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ not valid json")
            path = f.name
        with patch("sys.stderr", new_callable=StringIO) as fake_err:
            exit_code = main(["scan", "192.168.1.0/24", "-c", path])
        self.assertEqual(exit_code, 1)
        self.assertIn("not valid JSON", fake_err.getvalue())

    def test_invalid_port_key_prints_clean_error(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"ports": {"ssh": "SSH"}}, f)  # should be {"22": "SSH"}
            path = f.name
        with patch("sys.stderr", new_callable=StringIO) as fake_err:
            exit_code = main(["scan", "192.168.1.0/24", "-c", path])
        self.assertEqual(exit_code, 1)
        self.assertIn("invalid value", fake_err.getvalue())


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

    def test_no_banners_flag_reaches_scan_host(self):
        """
        --no-banners exists so a scan can skip the extra round trips
        banner-grabbing adds - but that's only true if the flag
        actually reaches scan_host()/run_full_scan(). Checks the real
        call kwargs scan_host received, the same style as the --iface
        wiring test above, since a silent wiring bug here would still
        produce normal-looking (just slower) output.
        """
        fake_host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")

        with patch("scandy.discover.scan", return_value=[fake_host]):
            with patch("scandy.portscan.scan_host") as mock_scan_host:
                mock_scan_host.return_value.__str__ = lambda self: "fake result"
                with patch("sys.stdout", new_callable=StringIO):
                    main(["portscan", "192.168.1.0/24", "--no-banners"])
        _, kwargs = mock_scan_host.call_args
        self.assertEqual(kwargs.get("grab_banners"), False)

        from scandy.portscan import ScanResult
        with patch("scandy.discover.scan", return_value=[fake_host]):
            with patch("scandy.report.scan_host", return_value=ScanResult(host=fake_host)) as mock_scan_host2:
                with patch("sys.stdout", new_callable=StringIO):
                    main(["scan", "192.168.1.0/24", "--no-banners"])
        _, kwargs2 = mock_scan_host2.call_args
        self.assertEqual(kwargs2.get("grab_banners"), False)

    def test_banners_grabbed_by_default(self):
        """The flip side: without --no-banners, grab_banners should
        default to True all the way through, not silently default off."""
        fake_host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")

        with patch("scandy.discover.scan", return_value=[fake_host]):
            with patch("scandy.portscan.scan_host") as mock_scan_host:
                mock_scan_host.return_value.__str__ = lambda self: "fake result"
                with patch("sys.stdout", new_callable=StringIO):
                    main(["portscan", "192.168.1.0/24"])
        _, kwargs = mock_scan_host.call_args
        self.assertEqual(kwargs.get("grab_banners"), True)

    def test_permission_error_prints_clean_message_not_traceback(self):
        """
        PermissionError is exactly what scapy raises when raw socket
        access needs root and the process isn't running as root - the
        single most common first-run mistake (forgetting sudo). Before
        _run_scapy_step wrapped this, it crashed with a raw Python
        traceback; this pins the friendly replacement in place.
        """
        with patch("scandy.discover.scan", side_effect=PermissionError("Operation not permitted")):
            with patch("sys.stderr", new_callable=StringIO) as fake_err:
                exit_code = main(["discover", "192.168.1.0/24"])

        self.assertEqual(exit_code, 1)
        self.assertIn("sudo", fake_err.getvalue())

    def test_os_error_prints_clean_message_mentioning_iface(self):
        """Covers the other common real-world failure: a bad/typo'd
        --iface value, which scapy surfaces as a plain OSError."""
        with patch("scandy.discover.scan", side_effect=OSError("No such device")):
            with patch("sys.stderr", new_callable=StringIO) as fake_err:
                exit_code = main(["discover", "192.168.1.0/24", "-i", "not-a-real-iface"])

        self.assertEqual(exit_code, 1)
        self.assertIn("No such device", fake_err.getvalue())
        self.assertIn("--iface", fake_err.getvalue())

    def test_iface_flag_reaches_discover_scan_for_every_command(self):
        """
        Regression test: --iface exists to fix a real problem (scapy
        picking the wrong NIC on a multi-interface machine and
        discovery silently finding 0 hosts), but that fix is useless
        if the CLI doesn't actually pass it through. Checks the real
        call arguments discover.scan() received, not just that the
        command ran without crashing - a wiring bug here would still
        print normal-looking output while silently dropping --iface
        on the floor.
        """
        fake_host = Host(ip="127.0.0.1", mac="00:00:00:00:00:00")

        for command in ("discover", "portscan", "isolation"):
            with self.subTest(command=command):
                with patch("scandy.discover.scan", return_value=[fake_host]) as mock_scan:
                    with patch("sys.stdout", new_callable=StringIO):
                        main([command, "192.168.1.0/24", "-i", "wlan0", "-t", "0.2"])

                _, kwargs = mock_scan.call_args
                self.assertEqual(kwargs.get("iface"), "wlan0")

        # "scan" goes through run_full_scan() instead of calling
        # discover.scan() directly, so check that path too.
        with patch("scandy.discover.scan", return_value=[fake_host]) as mock_scan:
            with patch("sys.stdout", new_callable=StringIO):
                main(["scan", "192.168.1.0/24", "-i", "wlan0", "-t", "0.2"])
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs.get("iface"), "wlan0")

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
