"""
Config file support.

Lets you override scan settings (ports to check, timeouts) via a JSON
file instead of editing code. Falls back to sane defaults when no
config file is given or a key is missing, so this is always optional.

Example config.json:
{
    "ports": {"22": "SSH", "80": "HTTP", "8080": "HTTP-alt"},
    "port_timeout": 0.5,
    "discover_timeout": 3
}
"""

import json
from dataclasses import dataclass, field

from netrecon.portscan import COMMON_PORTS

DEFAULT_PORT_TIMEOUT = 0.5
DEFAULT_DISCOVER_TIMEOUT = 3


@dataclass
class Config:
    ports: dict[int, str] = field(default_factory=lambda: dict(COMMON_PORTS))
    port_timeout: float = DEFAULT_PORT_TIMEOUT
    discover_timeout: int = DEFAULT_DISCOVER_TIMEOUT

    @classmethod
    def load(cls, path: str | None) -> "Config":
        """
        Load a Config from a JSON file. If path is None, returns the
        default Config untouched - callers don't need to branch on
        whether a config file was given.
        """
        if path is None:
            return cls()

        with open(path) as f:
            data = json.load(f)

        config = cls()

        # JSON object keys are always strings, but port numbers need to
        # be ints to match what portscan.py expects - convert here so
        # every other module can keep assuming int keys.
        if "ports" in data:
            config.ports = {int(port): name for port, name in data["ports"].items()}

        if "port_timeout" in data:
            config.port_timeout = float(data["port_timeout"])

        if "discover_timeout" in data:
            config.discover_timeout = int(data["discover_timeout"])

        return config
