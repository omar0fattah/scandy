"""
Shared data types with zero heavy dependencies.

Why this file exists: discover.py needs scapy (for raw ARP packets),
but portscan.py, isolation.py, and the report layer only need the
*shape* of a Host - they never touch scapy directly. If Host lived
inside discover.py, importing portscan.py would drag in scapy as a
side effect, even on a machine where you only want to test TCP logic.
Keeping plain data types dependency-free is a small thing that saves
real headaches later.
"""

from dataclasses import dataclass


@dataclass
class Host:
    ip: str
    mac: str

    def __str__(self):
        return f"{self.ip:<15}  {self.mac}"
