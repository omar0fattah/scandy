"""
Port scanning module.

Takes hosts found by discover.py and checks which TCP ports are open
on each one. This uses a plain "connect scan" - actually completing
the TCP handshake - rather than a raw SYN scan, because:

  1. It doesn't need root privileges (unlike a SYN scan).
  2. It's simpler to understand and debug when you're learning.
  3. It's reliable through things like client isolation tests later,
     since it behaves exactly like a normal application connecting.

The tradeoff: it's noisier (a completed connection is more likely to
show up in logs than a half-open SYN scan) and a bit slower. That's
a fine tradeoff for a learning tool on your own network.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from scandy.models import Host

# The ports most worth checking first - common services rather than
# all 65535. Scanning everything is possible but slow and mostly
# wasted effort on a home network.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP/misc",
    5353: "mDNS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


@dataclass
class ScanResult:
    host: Host
    open_ports: dict[int, str] = field(default_factory=dict)  # port -> service name

    def __str__(self):
        if not self.open_ports:
            return f"{self.host.ip:<15}  no open ports found"
        ports = ", ".join(f"{p}/{name}" for p, name in sorted(self.open_ports.items()))
        return f"{self.host.ip:<15}  {ports}"


def _check_port(ip: str, port: int, timeout: float) -> bool:
    """Try to complete a TCP handshake on ip:port. Returns True if open."""
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex returns 0 on success instead of raising an exception,
        # which is easier to handle in a tight loop than try/except.
        result = sock.connect_ex((ip, port))
        return result == 0


def scan_host(host: Host, ports: dict[int, str] = None, timeout: float = 0.5,
              max_workers: int = 50) -> ScanResult:
    """
    Scan one host across a set of ports, concurrently.

    ports: dict of {port: service_name}, defaults to COMMON_PORTS
    timeout: seconds to wait per connection attempt
    max_workers: how many ports to check in parallel - this is what
                 makes scanning fast; sequential would take forever
                 even for ~17 ports times timeout each.
    """
    ports = ports or COMMON_PORTS
    result = ScanResult(host=host)

    # ThreadPoolExecutor: sockets spend most of their time waiting on
    # the network, not using CPU, so threads (not processes) are the
    # right tool here - lightweight and plenty parallel for I/O waits.
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_check_port, host.ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                result.open_ports[port] = ports[port]

    return result


def scan_all(hosts: list[Host], ports: dict[int, str] = None,
             timeout: float = 0.5) -> list[ScanResult]:
    """Scan every host in the list. One host at a time, ports in parallel."""
    return [scan_host(h, ports=ports, timeout=timeout) for h in hosts]


if __name__ == "__main__":
    import argparse
    from scandy.discover import scan as discover_scan

    parser = argparse.ArgumentParser(description="Port scan hosts on a subnet")
    parser.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                         help="per-port timeout in seconds")
    args = parser.parse_args()

    print(f"Discovering hosts on {args.subnet} ...")
    hosts = discover_scan(args.subnet)
    print(f"Found {len(hosts)} host(s). Scanning ports...\n")

    for host in hosts:
        result = scan_host(host, timeout=args.timeout)
        print(result)
