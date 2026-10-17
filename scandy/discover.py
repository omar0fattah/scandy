"""
Host discovery module.

Sends ARP "who-has" requests to every address in a subnet and collects
replies. This only works on the local layer-2 segment you're plugged
into (ARP doesn't route), which is exactly the scope of "scan my home
network."

Why ARP instead of pinging every IP:
- It's how devices actually find each other on Ethernet/Wi-Fi, so it's
  fast and reliable even for hosts that block ICMP (ping).
- A single broadcast ARP request can hit the whole subnet at once.

Requires root/administrator privileges because it crafts raw packets.
"""

from scapy.all import ARP, Ether, srp

from scandy.models import Host


def scan(subnet: str, timeout: int = 3, iface: str | None = None) -> list[Host]:
    """
    Scan a subnet for live hosts using ARP.

    subnet: CIDR notation, e.g. "192.168.1.0/24"
    timeout: seconds to wait for replies
    iface: network interface to send the ARP broadcast on (e.g. "eth0",
        "wlan0"). If None (the default), scapy picks its own default
        interface (conf.iface) - usually fine on a machine with one
        active network connection, but on anything with multiple
        interfaces (very common for a VM: a NAT adapter plus a
        host-only/bridged one, or a laptop with both Wi-Fi and
        Ethernet), scapy can guess the wrong one. The broadcast still
        "succeeds" with no error, it just goes out the wrong NIC, so
        the scan silently returns zero hosts instead of failing
        loudly - that looks exactly like a bug even though nothing
        is actually broken. Run `ip addr` (Linux) to see interface
        names and pass the right one explicitly if discover() keeps
        finding nothing on a network you know has live hosts.

    Returns a list of Host objects for every device that answered.
    """
    # Build one ARP request packet targeted at the whole subnet.
    # pdst accepts CIDR notation and scapy expands it internally.
    arp_request = ARP(pdst=subnet)

    # Ethernet frames need a destination MAC. ff:ff:ff:ff:ff:ff is the
    # broadcast address - "every device on this segment, please listen."
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Stack them: broadcast Ethernet frame carrying the ARP request.
    packet = broadcast / arp_request

    # srp = "send and receive at layer 2". It returns two lists:
    # answered (request, reply) pairs, and unanswered requests (ignored).
    # iface=None here matches srp()'s own default (use conf.iface), so
    # passing it through unconditionally is safe either way.
    answered, _unanswered = srp(packet, timeout=timeout, iface=iface, verbose=False)

    hosts = []
    for _sent, received in answered:
        hosts.append(Host(ip=received.psrc, mac=received.hwsrc))

    # Sort by IP for a readable report (string sort is wrong for IPs,
    # so sort by the numeric octets instead).
    hosts.sort(key=lambda h: tuple(int(octet) for octet in h.ip.split(".")))
    return hosts


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARP host discovery")
    parser.add_argument("subnet", help="CIDR to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-i", "--iface", default=None,
                         help="network interface to use (e.g. eth0, wlan0) - "
                              "see `ip addr` if the default picks the wrong one")
    args = parser.parse_args()

    print(f"Scanning {args.subnet} ...\n")
    found = scan(args.subnet, timeout=args.timeout, iface=args.iface)

    if not found:
        print("No hosts responded. Check the subnet or run with sudo.")
    else:
        print(f"{'IP':<15}  MAC")
        print("-" * 36)
        for host in found:
            print(host)
        print(f"\n{len(found)} host(s) found.")
