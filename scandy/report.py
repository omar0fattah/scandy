"""
Reporting layer.

This ties discover.py, portscan.py, isolation.py, and bypass.py
together into one run and one readable summary, so the user doesn't
have to run four scripts and mentally merge the output themselves.

Intended use: your own home/lab network, with permission. This tool
does not attempt anything against networks you don't control.
"""

import json
from dataclasses import dataclass, field

from scandy import colors
from scandy.models import Host
from scandy.portscan import scan_host, ScanResult
from scandy.isolation import check_host, IsolationReport, summarize as summarize_isolation


@dataclass
class NetworkReport:
    subnet: str
    hosts: list[Host] = field(default_factory=list)
    port_results: list[ScanResult] = field(default_factory=list)
    isolation_results: list[IsolationReport] = field(default_factory=list)

    def render(self, color: bool = False) -> str:
        """
        Render the report as plain text.

        color=False (the default) produces plain text with zero ANSI
        codes - safe to write straight to a file. color=True adds
        color for terminal display; colors.py still auto-disables
        itself on a non-tty or when NO_COLOR is set, so this is a
        request for color, not a guarantee of it. The two are kept
        separate on purpose: the exact same NetworkReport is often
        both printed to the terminal AND saved to a file in the same
        run (see __main__ below), and a saved file should never end
        up with embedded escape codes just because it happened to
        also be printed to a colored terminal first.
        """
        lines = []
        lines.append(f"=== Network Recon Report: {self.subnet} ===\n")

        lines.append(f"Hosts found: {len(self.hosts)}")
        for host in self.hosts:
            lines.append(f"  {host}")
        lines.append("")

        lines.append("Open ports per host:")
        for result in self.port_results:
            lines.append(f"  {self._render_port_result(result, color)}")
        lines.append("")

        lines.append("Isolation check:")
        for report in self.isolation_results:
            lines.append(f"  {self._render_isolation_report(report, color)}")

        verdict = summarize_isolation(self.isolation_results)
        if color:
            verdict = colors.bold(verdict)
        lines.append(f"\n  Verdict: {verdict}")

        return "\n".join(lines)

    @staticmethod
    def _render_port_result(result: ScanResult, color: bool) -> str:
        if not result.open_ports:
            tail = "no open ports found"
            if color:
                tail = colors.yellow(tail)
            return f"{result.host.ip:<15}  {tail}"

        ports = ", ".join(f"{p}/{name}" for p, name in sorted(result.open_ports.items()))
        if color:
            ports = colors.green(ports)
        return f"{result.host.ip:<15}  {ports}"

    @staticmethod
    def _render_isolation_report(report: IsolationReport, color: bool) -> str:
        verdict = "ISOLATED (likely)" if report.likely_isolated else "reachable"
        if color:
            verdict = colors.red(verdict) if report.likely_isolated else colors.green(verdict)
        return (f"{report.host.ip:<15}  arp={report.arp_reachable}  "
                f"tcp={report.tcp_reachable}  -> {verdict}")

    def to_dict(self) -> dict:
        """
        Build a plain-dict representation safe for json.dumps - no
        dataclass or custom objects left inside, just str/int/bool/
        list/dict, so this can be fed into other tools later (a
        dashboard, a diff-against-last-scan script, whatever) without
        them needing to know about scandy's internal classes.
        """
        return {
            "subnet": self.subnet,
            "hosts": [{"ip": h.ip, "mac": h.mac} for h in self.hosts],
            "port_results": [
                {
                    "ip": r.host.ip,
                    "open_ports": {str(port): name for port, name in r.open_ports.items()},
                }
                for r in self.port_results
            ],
            "isolation_results": [
                {
                    "ip": r.host.ip,
                    "arp_reachable": r.arp_reachable,
                    "tcp_reachable": r.tcp_reachable,
                    "likely_isolated": r.likely_isolated,
                }
                for r in self.isolation_results
            ],
            "isolation_verdict": summarize_isolation(self.isolation_results),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def run_full_scan(subnet: str, port_timeout: float = 0.5, discover_timeout: int = 3,
                   iface: str | None = None) -> NetworkReport:
    """
    Run the full pipeline: discover hosts, scan their ports, and check
    for isolation. Returns a NetworkReport the caller can render or
    inspect programmatically.

    discover_timeout/iface are passed straight through to discover.scan()
    - see that function's docstring for why iface matters (scapy can
    silently pick the wrong network interface on a multi-NIC machine,
    e.g. a VM with more than one adapter, and the scan just quietly
    returns zero hosts instead of erroring).

    discover.py is imported here, not at module level, so that
    anything only using NetworkReport/render() (like tests, or a
    future script that formats results some other way) doesn't need
    scapy installed just to import this module.
    """
    from scandy.discover import scan as discover_hosts

    hosts = discover_hosts(subnet, timeout=discover_timeout, iface=iface)

    port_results = [scan_host(h, timeout=port_timeout) for h in hosts]
    isolation_results = [check_host(h, timeout=port_timeout) for h in hosts]

    return NetworkReport(
        subnet=subnet,
        hosts=hosts,
        port_results=port_results,
        isolation_results=isolation_results,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Full network recon report")
    parser.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--timeout", type=float, default=0.5)
    parser.add_argument("-o", "--output", help="save report to a text file")
    args = parser.parse_args()

    print(f"Running full scan on {args.subnet} ...\n")
    report = run_full_scan(args.subnet, port_timeout=args.timeout)
    text = report.render()

    print(text)

    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"\nSaved report to {args.output}")
