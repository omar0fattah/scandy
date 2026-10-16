# scandy

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
sudo python3 -m scandy discover 192.168.1.0/24

# Discover + port scan
sudo python3 -m scandy portscan 192.168.1.0/24

# Discover + isolation check
sudo python3 -m scandy isolation 192.168.1.0/24

# Full pipeline: discover + portscan + isolation, with a report
sudo python3 -m scandy scan 192.168.1.0/24

# Save as JSON instead of text
sudo python3 -m scandy scan 192.168.1.0/24 --json -o report.json

# Use a custom config (ports, timeouts)
sudo python3 -m scandy scan 192.168.1.0/24 -c myconfig.json
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
| `scandy/models.py` | Shared `Host` data type | No |
| `scandy/discover.py` | ARP host discovery | Yes |
| `scandy/portscan.py` | TCP connect-scan common ports | No |
| `scandy/isolation.py` | Detects likely client isolation | No |
| `scandy/bypass.py` | SSDP multicast leak test + gateway relay test | Partially (relay test needs scapy) |
| `scandy/report.py` | Combines everything into one report (text/JSON) | No (only `run_full_scan`) |
| `scandy/config.py` | Loads custom ports/timeouts from JSON | No |
| `scandy/colors.py` | Terminal color helpers | No |
| `scandy/cli.py` | Unified `python3 -m scandy ...` entry point | No (imports are lazy per-command) |

## Running tests

```bash
python3 -m unittest discover -v
```

The full suite (35 tests) passes whether or not scapy is actually
installed. Most tests are pure socket/logic tests that never touch
scapy at all; the ones that do (`discover.py`'s reply parsing,
`bypass.py`'s gateway relay check) run against a minimal scapy stub
(`tests/_fake_scapy.py`) so the surrounding logic is verified even in
an environment without real scapy. That stub only proves scandy's own
code does the right thing with whatever scapy/a real network hands
it — it doesn't verify real ARP/packet behavior, which only a live
run on your own network can confirm.

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



**NOTE** : this tool is made with the help of AI please feel free to contact me if there's an error with the file , Thank you.
