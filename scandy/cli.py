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
import json
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
                        help="override timeout in seconds (applies to both "
                             "discovery and port/isolation checks)")
        p.add_argument("-c", "--config", help="path to a JSON config file")
        p.add_argument("-i", "--iface", default=None,
                        help="network interface for ARP discovery (e.g. eth0, "
                             "wlan0) - see `ip addr`; needed if discovery finds "
                             "0 hosts on a machine with more than one network "
                             "interface, since the default can pick the wrong one")

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


def _run_scapy_step(fn):
    """
    Run a scapy-touching call (ARP discovery, the gateway relay probe)
    and turn the most common real-world failures into a clear message
    instead of a raw traceback - this is the first thing most people
    hit on their first run, not an edge case:

    - PermissionError / OSError "Operation not permitted": raw socket
      access needs root (sudo on Linux/macOS, Administrator + Npcap on
      Windows). This is the #1 thing people forget.
    - OSError mentioning the interface: usually a typo'd --iface value
      - see `ip addr` for real interface names.

    Returns the function's result, or None if it failed (the caller
    checks for None and returns a non-zero exit code).
    """
    try:
        return fn()
    except PermissionError:
        print(
            "Error: permission denied. Raw packet access needs elevated "
            "privileges - run this with sudo (Linux/macOS) or as "
            "Administrator with Npcap installed (Windows).",
            file=sys.stderr,
        )
        return None
    except OSError as e:
        print(f"Error: network operation failed ({e}). If you passed "
              f"--iface, double check the interface name with `ip addr`.",
              file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = Config.load(args.config)
    except FileNotFoundError:
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: {args.config} is not valid JSON ({e})", file=sys.stderr)
        return 1
    except ValueError as e:
        # Covers a non-numeric port key/timeout, e.g. {"ports": {"ssh": "SSH"}}
        # instead of {"ports": {"22": "SSH"}} - a typo'd config shouldn't
        # crash with a raw traceback, it should say what's wrong.
        print(f"Error: invalid value in {args.config} ({e})", file=sys.stderr)
        return 1

    # A single --timeout, when given, overrides both the discovery
    # timeout and the port/isolation-check timeout - simpler than two
    # separate flags, and config.json can still set them independently
    # when --timeout isn't passed.
    discover_timeout = int(args.timeout) if args.timeout is not None else config.discover_timeout
    check_timeout = args.timeout if args.timeout is not None else config.port_timeout

    if args.command == "discover":
        from scandy.discover import scan as discover_scan
        hosts = _run_scapy_step(
            lambda: discover_scan(args.subnet, timeout=discover_timeout, iface=args.iface)
        )
        if hosts is None:
            return 1
        for host in hosts:
            print(host)
        print(f"\n{len(hosts)} host(s) found.")
        return 0

    if args.command == "portscan":
        from scandy.discover import scan as discover_scan
        from scandy.portscan import scan_host
        hosts = _run_scapy_step(
            lambda: discover_scan(args.subnet, timeout=discover_timeout, iface=args.iface)
        )
        if hosts is None:
            return 1
        for host in hosts:
            print(scan_host(host, ports=config.ports, timeout=check_timeout))
        return 0

    if args.command == "isolation":
        from scandy.discover import scan as discover_scan
        from scandy.isolation import check_host, summarize
        hosts = _run_scapy_step(
            lambda: discover_scan(args.subnet, timeout=discover_timeout, iface=args.iface)
        )
        if hosts is None:
            return 1
        reports = [check_host(h, timeout=check_timeout) for h in hosts]
        for r in reports:
            print(r)
        print(f"\n{summarize(reports)}")
        return 0

    if args.command == "scan":
        from scandy.report import run_full_scan
        report = _run_scapy_step(
            lambda: run_full_scan(args.subnet, port_timeout=check_timeout,
                                   discover_timeout=discover_timeout, iface=args.iface)
        )
        if report is None:
            return 1

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
