"""
Client isolation bypass probes.

Two distinct techniques live here, with very different testability:

1. ssdp_probe() - multicast discovery leak test.
   Client isolation is usually implemented by the AP dropping *unicast*
   frames between two wireless clients. Multicast/broadcast traffic
   (used by device-discovery protocols like SSDP/UPnP and mDNS) is
   handled differently in the AP's forwarding logic, and on some
   hardware it still gets relayed even when unicast isolation is on.
   So: send an SSDP "M-SEARCH" discovery query (the same kind your
   smart TV or printer uses to announce itself) and see who answers.
   If devices respond that unicast port scans couldn't reach, that's
   a real isolation leak. Pure standard-library sockets - no scapy,
   no root, so this is testable right now.

2. gateway_relay_check() - Layer 3 routing leak test.
   AP isolation is a Wi-Fi *driver/firmware* feature that blocks
   frames between two clients directly. But the gateway/router is a
   separate device on the same network, and some consumer routers
   will happily route (Layer 3) traffic between two devices on the
   same subnet even if the AP won't bridge (Layer 2) them directly.
   The test: craft a packet addressed to the gateway's MAC at Layer 2,
   but to the target's IP at Layer 3, and see if the gateway forwards
   it. This needs raw packet crafting (scapy) and root, and its result
   depends entirely on real router firmware - it can only be
   meaningfully tested on your actual network, not simulated here.
"""

import socket
import time

SSDP_GROUP = ("239.255.255.250", 1900)
SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def _collect_replies(sock: socket.socket, timeout: float) -> list[str]:
    """
    Read datagrams off `sock` until `timeout` seconds have passed total,
    returning the sorted list of unique source IPs that sent something.

    Split out from ssdp_probe() specifically so it can be unit tested
    with a plain loopback UDP socket - the receive-until-timeout loop
    is the part most likely to have bugs (infinite loop, swallowing
    the wrong exception, not resetting the deadline correctly), and
    none of that requires real multicast to verify.
    """
    responders = set()
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            _data, addr = sock.recvfrom(4096)
            responders.add(addr[0])
        except (socket.timeout, OSError):
            break
    return sorted(responders)


def ssdp_probe(timeout: float = 2.0) -> list[str]:
    """
    Send an SSDP multicast discovery query and collect responding IPs.

    Run this ALONGSIDE isolation.py's unicast check: if isolation.py
    says a host is unreachable but it answers here, that's evidence
    multicast is leaking across the isolation boundary even though
    direct connections are blocked.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(SSDP_REQUEST.encode(), SSDP_GROUP)
        return _collect_replies(sock, timeout)
    finally:
        sock.close()


def gateway_relay_check(gateway_ip: str, target_ip: str, port: int = 80,
                         timeout: float = 2.0) -> bool:
    """
    Test whether the gateway will route traffic to an isolated target
    even when direct Layer 2 traffic to it is blocked.

    Requires scapy + root. Only meaningful against a real router, so
    this can't be verified in a sandbox - treat it as untested until
    you run it on your own network.
    """
    from scapy.all import ARP, Ether, IP, TCP, srp, srp1

    # First, resolve the gateway's MAC - we need it to build the frame below.
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    answered, _ = srp(arp_request, timeout=timeout, verbose=False)
    if not answered:
        return False  # can't even reach the gateway - nothing to test

    gateway_mac = answered[0][1].hwsrc

    # The actual test packet: Ethernet frame addressed to the GATEWAY's
    # MAC, but an IP payload addressed to the TARGET's IP. A plain L2
    # switch/AP would just forward this toward the gateway and the
    # gateway would likely drop it (wrong destination). But a router
    # doing IP-level forwarding between its own interfaces may instead
    # route it on to the real target - that's the leak we're testing for.
    packet = Ether(dst=gateway_mac) / IP(dst=target_ip) / TCP(dport=port, flags="S")
    reply = srp1(packet, timeout=timeout, verbose=False)

    if reply is None or not reply.haslayer(TCP):
        return False

    # SYN-ACK (flags 0x12) means the target actually responded - relay worked.
    return bool(reply[TCP].flags & 0x12)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Client isolation bypass probes")
    parser.add_argument("--ssdp", action="store_true", help="run SSDP multicast leak test")
    parser.add_argument("--gateway", help="gateway IP, for relay test")
    parser.add_argument("--target", help="target IP, for relay test")
    args = parser.parse_args()

    if args.ssdp:
        print("Sending SSDP discovery probe...")
        responders = ssdp_probe()
        if responders:
            print(f"{len(responders)} device(s) responded to multicast:")
            for ip in responders:
                print(f"  {ip}")
        else:
            print("No multicast responses - either nothing supports SSDP, or it's blocked too.")

    if args.gateway and args.target:
        print(f"\nTesting gateway relay: {args.gateway} -> {args.target} ...")
        result = gateway_relay_check(args.gateway, args.target)
        print("Relay WORKED (isolation bypassed)" if result else "Relay failed (isolation held)")
