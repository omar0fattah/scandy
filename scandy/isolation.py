"""
Client (AP) isolation detection.

What client isolation actually is:
    Normally, every device on a Wi-Fi network can talk to every other
    device on that same network directly - that's just how a switch/AP
    works, it forwards frames between connected clients. "Client
    isolation" (also called AP isolation) is a setting where the
    access point refuses to forward traffic *between* two wireless
    clients. Each client can still reach the internet (via the
    gateway), but not each other.

    This is a legitimate security feature, common on:
      - Guest Wi-Fi networks (so guests can't poke at each other)
      - Public hotspots (cafes, airports)
      - Some home routers as an optional setting

How we detect it, without needing two separate test devices:
    We already have a list of live hosts from discover.py. The
    simplest test is: can THIS machine (wherever this script is
    running) reach other hosts on the LAN at the TCP level, beyond
    just getting an ARP reply?

    ARP replies alone don't prove isolation is off - some AP isolation
    implementations still let ARP broadcasts through but then drop the
    actual data frames between clients. So the real test is: after
    finding a host via ARP, can we actually open a TCP connection to
    it? If ARP says "host is there" but every TCP attempt times out
    (and it's not just a host with a firewall), that's the isolation
    signature.

    This is a heuristic, not a certainty - a host with every port
    firewalled would look identical to an isolated host. Scanning
    more ports and hosts makes the signal more reliable.
"""

from dataclasses import dataclass

from scandy.models import Host
from scandy.portscan import COMMON_PORTS, _check_port


@dataclass
class IsolationReport:
    host: Host
    arp_reachable: bool       # did it answer ARP? (always True if it's in our host list)
    tcp_reachable: bool       # did ANY port respond at the TCP level?
    likely_isolated: bool     # our best guess

    def __str__(self):
        verdict = "ISOLATED (likely)" if self.likely_isolated else "reachable"
        return f"{self.host.ip:<15}  arp={self.arp_reachable}  tcp={self.tcp_reachable}  -> {verdict}"


def check_host(host: Host, timeout: float = 0.5) -> IsolationReport:
    """
    Test one host for isolation signs by trying several common ports.
    If ANY port responds (open OR actively refused, both prove a real
    TCP-level reply came back), isolation is not blocking this host.
    """
    reachable = False
    for port in COMMON_PORTS:
        # We only need one successful connection to disprove isolation.
        if _check_port(host.ip, port, timeout):
            reachable = True
            break

    return IsolationReport(
        host=host,
        arp_reachable=True,  # it's in our list, so it already answered ARP
        tcp_reachable=reachable,
        # If ARP works but we can't open a single TCP connection across
        # ~17 common ports, isolation (or a very locked-down host) is
        # the most likely explanation.
        likely_isolated=not reachable,
    )


def check_all(hosts: list[Host], timeout: float = 0.5) -> list[IsolationReport]:
    return [check_host(h, timeout=timeout) for h in hosts]


def summarize(reports: list[IsolationReport]) -> str:
    """One-line network-wide verdict, for the final brief."""
    total = len(reports)
    isolated = sum(1 for r in reports if r.likely_isolated)

    if total == 0:
        return "No hosts to evaluate."
    if isolated == 0:
        return f"No isolation detected - all {total} host(s) were TCP-reachable."
    if isolated == total:
        return f"Client isolation likely ACTIVE - all {total} host(s) were unreachable at TCP level."
    return (f"Mixed results: {isolated}/{total} host(s) unreachable. "
            f"Could be partial isolation, firewalls on specific hosts, or false positives "
            f"(host just has no open ports) - worth checking manually.")


if __name__ == "__main__":
    import argparse
    from scandy.discover import scan as discover_scan

    parser = argparse.ArgumentParser(description="Check for client isolation on a subnet")
    parser.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
    args = parser.parse_args()

    print(f"Discovering hosts on {args.subnet} ...")
    hosts = discover_scan(args.subnet)
    print(f"Found {len(hosts)} host(s). Checking reachability...\n")

    reports = check_all(hosts)
    for r in reports:
        print(r)

    print(f"\n{summarize(reports)}")
