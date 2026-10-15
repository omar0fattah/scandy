"""
Real functional tests for config.py - actual file I/O, actual JSON
parsing, not mocked.
"""

import json
import os
import tempfile
import unittest

from scandy.config import Config, DEFAULT_PORT_TIMEOUT
from scandy.portscan import COMMON_PORTS


class TestConfig(unittest.TestCase):
    def test_no_path_returns_defaults(self):
        config = Config.load(None)
        self.assertEqual(config.ports, dict(COMMON_PORTS))
        self.assertEqual(config.port_timeout, DEFAULT_PORT_TIMEOUT)

    def test_loads_custom_ports_and_timeout_from_file(self):
        data = {
            "ports": {"22": "SSH", "9999": "custom-service"},
            "port_timeout": 1.5,
            "discover_timeout": 5,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            config = Config.load(path)
            # Keys must be real ints, not strings, since portscan.py
            # indexes into this dict with int port numbers.
            self.assertEqual(config.ports, {22: "SSH", 9999: "custom-service"})
            self.assertIsInstance(list(config.ports.keys())[0], int)
            self.assertEqual(config.port_timeout, 1.5)
            self.assertEqual(config.discover_timeout, 5)
        finally:
            os.unlink(path)

    def test_partial_config_falls_back_to_defaults_for_missing_keys(self):
        # Only overriding port_timeout - ports and discover_timeout
        # should still come out as defaults.
        data = {"port_timeout": 2.0}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        try:
            config = Config.load(path)
            self.assertEqual(config.ports, dict(COMMON_PORTS))
            self.assertEqual(config.port_timeout, 2.0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
