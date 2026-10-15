# netrecon

A home/lab network recon tool: discovers live hosts, scans common ports,
checks for client (AP) isolation, and summarizes it all into one report.

**Only run this against networks you own or have explicit permission to
test.** This is a learning project built step by step while studying
networking and offensive security fundamentals.

## Setup

Needs Python 3.10+ and root/admin privileges (raw packet access for ARP).

```bash
pip install -r requirements.txt
```

On Windows, scapy also needs [Npcap](https://npcap.com/) installed first.

## Usage

```bash
# Host discovery only
sudo python3 -m netrecon discover 192.168.1.0/24

# Discover + port scan
sudo python3 -m netrecon portscan 192.168.1.0/24

# Discover + isolation check
sudo python3 -m netrecon isolation 192.168.1.0/24

# Full pipeline: discover + portscan + isolation, with a report
sudo python3 -m netrecon scan 192.168.1.0/24

# Save as JSON instead of text
sudo python3 -m netrecon scan 192.168.1.0/24 --json -o report.json

# Use a custom config (ports, timeouts)
sudo python3 -m netrecon scan 192.168.1.0/24 -c myconfig.json
```

### Example config file

```json
{
  "ports": {"22": "SSH", "80": "HTTP", "443": "HTTPS"},
  "port_timeout": 0.5,
  "discover_timeout": 3
}
```

## Project layout

| File | What it does | Needs scapy/root? |
|---|---|---|
| `netrecon/models.py` | Shared `Host` data type | No |
| `netrecon/discover.py` | ARP host discovery | Yes |
| `netrecon/portscan.py` | TCP connect-scan common ports | No |
| `netrecon/isolation.py` | Detects likely client isolation | No |
| `netrecon/bypass.py` | SSDP multicast leak test + gateway relay test | Partially (relay test needs scapy) |
| `netrecon/report.py` | Combines everything into one report (text/JSON) | No (only `run_full_scan`) |
| `netrecon/config.py` | Loads custom ports/timeouts from JSON | No |
| `netrecon/colors.py` | Terminal color helpers | No |
| `netrecon/cli.py` | Unified `python3 -m netrecon ...` entry point | No (imports are lazy per-command) |

## Running tests

```bash
python3 -m unittest discover -v
```

Most of the test suite runs without scapy installed (pure socket/logic
tests). A couple of CLI dispatch tests are skipped automatically if
scapy isn't importable, since they patch `netrecon.discover.scan`.

## How client isolation detection works

Client isolation (AP isolation) stops wireless clients on the same
network from reaching each other directly, while still letting each
one reach the internet through the gateway. `isolation.py` detects it
as a heuristic: a host that answers ARP (so it's clearly on the
network) but doesn't respond on any common TCP port is a strong signal
of isolation. `bypass.py` then tests two known ways isolation
sometimes leaks:

- **Multicast/SSDP leak**: some AP firmware blocks unicast traffic
  between clients but still relays multicast discovery traffic.
- **Gateway relay**: some routers will route traffic between two
  clients at Layer 3 even when the AP won't bridge them at Layer 2.

Both are documented, known weaknesses in some consumer AP
implementations - not secret exploits - and both only make sense to
test on a network you control.
