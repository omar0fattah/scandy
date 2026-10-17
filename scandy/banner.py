"""
Service banner grabbing.

portscan.py tells you a port is open. This tells you what's actually
running there - the difference between "22/SSH is open" and "22/SSH
is open, running OpenSSH 7.4" is the difference between "something's
there" and "something's there, here's what to look up."

Two grabbing strategies, because services behave differently:

1. Passive banner read - SSH, FTP, SMTP, POP3, IMAP and several
   others send a greeting line immediately after the TCP handshake
   completes, before the client says anything. Just connect and read.

2. Active HTTP(S) probe - HTTP servers wait for the client to send a
   request first (no banner on connect), so this sends a minimal HEAD
   request and reads back the response, particularly the `Server`
   header. HTTPS needs the exact same thing wrapped in TLS.

This stays strictly informational: identify what's running and its
version string, nothing more. No exploit code, no automated "now do
something about it" - that line is deliberate, not a missing feature.
Known-CVE lookup against a version string is a reasonable follow-up
on top of this, but isn't part of this module.
"""

import socket
import ssl
from dataclasses import dataclass, field

# Ports where a request has to be sent before anything comes back.
HTTP_PORTS = {80, 8080, 5000}
HTTPS_PORTS = {443, 8443}


def _read_passive_banner(ip: str, port: int, timeout: float) -> str | None:
    """
    Connect and read whatever the service sends first, without us
    sending anything - works for SSH/FTP/SMTP/POP3/IMAP and similar
    greeting-on-connect protocols, including non-standard ports running
    one of these (we don't gate this on a port allowlist, since a
    service moved to an unusual port still behaves the same way).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            data = sock.recv(256)
            return data.decode(errors="replace").strip() or None
    except (socket.timeout, OSError):
        return None


def _probe_http(ip: str, port: int, timeout: float, use_tls: bool) -> str | None:
    """
    Send a minimal HTTP request and return whatever comes back (status
    line + headers, which includes `Server` when the service sends
    one). HTTPS wraps the same socket in TLS - certificate verification
    is intentionally disabled here since this only grabs a banner, it
    never trusts the connection for anything sensitive.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if use_tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=ip)

        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        data = sock.recv(4096)
        return data.decode(errors="replace").strip() or None
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        if sock is not None:
            sock.close()


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """
    Try to identify what's running on ip:port. Returns the raw banner
    text (passive greeting, or key HTTP response lines) if anything
    came back, else None - None just means nothing was grabbed, it
    doesn't mean the port isn't open (portscan.py already confirmed
    that separately).
    """
    if port in HTTPS_PORTS:
        return _probe_http(ip, port, timeout, use_tls=True)
    if port in HTTP_PORTS:
        return _probe_http(ip, port, timeout, use_tls=False)
    return _read_passive_banner(ip, port, timeout)


def grab_banners(ip: str, ports: dict, timeout: float = 2.0) -> dict[int, str]:
    """
    Grab banners for a dict of {port: service_name} - the same shape
    as ScanResult.open_ports. Returns {port: banner_text}, only
    including ports where something was actually grabbed (a port with
    no banner is left out rather than stored as None, so callers can
    just check `if port in banners` instead of checking for None).
    """
    results = {}
    for port in ports:
        banner = grab_banner(ip, port, timeout=timeout)
        if banner:
            results[port] = banner
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Grab a service banner from a single host:port")
    parser.add_argument("ip", help="target IP")
    parser.add_argument("port", type=int)
    parser.add_argument("-t", "--timeout", type=float, default=2.0)
    args = parser.parse_args()

    banner = grab_banner(args.ip, args.port, timeout=args.timeout)
    if banner:
        print(banner)
    else:
        print("No banner grabbed (port may be closed, filtered, or silent until spoken to).")
