"""
Unified CLI entry point.

Before this, running anything meant remembering which module path did
what (python3 -m scandy.discover, python3 -m scandy.portscan,
...). This collects them into one command with subcommands, the way
real tools like `git` or `nmap --script` do it:

    python3 -m scandy discover 192.168.1.0/24
    python3 -m scandy portscan 192.168.1.0/24
    python3 -m scandy isolation 192.168.1.0/24
    python3 -m scandy scan 192.168.1.0/24          (full pipeline)
    python3 -m scandy scan 192.168.1.0/24 -o report.json --json

Only the "scan" (full pipeline) and "discover" subcommands touch
scapy/raw sockets - argument parsing and dispatch here stay import-
light so --help works even on a machine without scapy installed.
"""

import argparse
import sys

from scandy.config import Config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scandy",
        description="Home/lab network recon: discovery, port scanning, isolation checks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_args(p):
        p.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
        p.add_argument("-t", "--timeout", type=float, default=None,
                        help="override timeout in seconds")
        p.add_argument("-c", "--config", help="path to a JSON config file")

    p_discover = sub.add_parser("discover", help="find live hosts on a subnet (ARP)")
    add_common_args(p_discover)

    p_portscan = sub.add_parser("portscan", help="discover hosts, then port-scan each")
    add_common_args(p_portscan)

    p_isolation = sub.add_parser("isolation", help="discover hosts, then check for client isolation")
    add_common_args(p_isolation)

    p_scan = sub.add_parser("scan", help="full pipeline: discover + portscan + isolation")
    add_common_args(p_scan)
    p_scan.add_argument("-o", "--output", help="save report to this file")
    p_scan.add_argument("--json", action="store_true", help="output/save as JSON instead of text")
    p_scan.add_argument("--no-color", action="store_true", help="disable colored terminal output")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = Config.load(args.config)

    if args.command == "discover":
        from scandy.discover import scan as discover_scan
        timeout = args.timeout if args.timeout is not None else config.discover_timeout
        hosts = discover_scan(args.subnet, timeout=int(timeout))
        for host in hosts:
            print(host)
        print(f"\n{len(hosts)} host(s) found.")
        return 0

    if args.command == "portscan":
        from scandy.discover import scan as discover_scan
        from scandy.portscan import scan_host
        timeout = args.timeout if args.timeout is not None else config.port_timeout
        hosts = discover_scan(args.subnet)
        for host in hosts:
            print(scan_host(host, ports=config.ports, timeout=timeout))
        return 0

    if args.command == "isolation":
        from scandy.discover import scan as discover_scan
        from scandy.isolation import check_host, summarize
        timeout = args.timeout if args.timeout is not None else config.port_timeout
        hosts = discover_scan(args.subnet)
        reports = [check_host(h, timeout=timeout) for h in hosts]
        for r in reports:
            print(r)
        print(f"\n{summarize(reports)}")
        return 0

    if args.command == "scan":
        from scandy.report import run_full_scan
        timeout = args.timeout if args.timeout is not None else config.port_timeout
        report = run_full_scan(args.subnet, port_timeout=timeout)

        if args.json:
            text = report.to_json()
        else:
            text = report.render(color=not args.no_color)

        print(text)

        if args.output:
            # Always save the plain (uncolored) form to a file, and
            # match the format actually requested - a saved .json
            # report shouldn't silently be text, or vice versa.
            save_text = report.to_json() if args.json else report.render(color=False)
            with open(args.output, "w") as f:
                f.write(save_text)
            print(f"\nSaved report to {args.output}", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
