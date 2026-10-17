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

**On Kali/Debian (and other recent distros)**, plain `pip install` may
refuse with `error: externally-managed-environment` (PEP 668). Two
ways around it:

```bash
# Either: install just for this project in a venv (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# then run everything with: sudo venv/bin/python3 -m scandy ...
# (plain `sudo python3 -m scandy ...` won't see the venv - sudo
# starts a fresh environment that doesn't inherit `source activate`)

# Or: install system-wide, which is also what root's python needs anyway
sudo pip install --break-system-packages -r requirements.txt
```

The second option is simpler for a one-off test since this tool needs
`sudo` either way, but a venv is the better habit generally.

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

# If discovery finds 0 hosts on a network you know has live devices,
# scapy may have picked the wrong network interface (common on VMs
# with more than one virtual adapter). Check `ip addr` for the real
# interface name and specify it explicitly:
sudo python3 -m scandy scan 192.168.1.0/24 -i eth0

# Skip service/version banner grabbing for a faster, quieter scan
sudo python3 -m scandy scan 192.168.1.0/24 --no-banners
```

If you forget `sudo`, you'll get a clear "permission denied" message
instead of a crash - raw packet access always needs it.

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
| `scandy/banner.py` | Grabs a service banner/version string from open ports | No |
| `scandy/report.py` | Combines everything into one report (text/JSON) | No (only `run_full_scan`) |
| `scandy/config.py` | Loads custom ports/timeouts from JSON | No |
| `scandy/colors.py` | Terminal color helpers | No |
| `scandy/cli.py` | Unified `python3 -m scandy ...` entry point | No (imports are lazy per-command) |

## Running tests

```bash
python3 -m unittest discover -v
```

The full suite (56 tests) passes whether or not scapy is actually
installed. Most tests are pure socket/logic tests that never touch
scapy at all; the ones that do (`discover.py`'s reply parsing,
`bypass.py`'s gateway relay check) run against a minimal scapy stub
(`tests/_fake_scapy.py`) so the surrounding logic is verified even in
an environment without real scapy. That stub only proves scandy's own
code does the right thing with whatever scapy/a real network hands
it — it doesn't verify real ARP/packet behavior, which only a live
run on your own network can confirm.

## Service banner grabbing

Once `portscan.py` finds an open port, `banner.py` tries to identify
what's actually running there — the difference between "22/SSH is
open" and "22/SSH is open, running OpenSSH 9.6". This runs
automatically as part of `portscan` and `scan` (use `--no-banners` to
skip it for a faster, quieter run). Two strategies, picked by port:

- **Passive read**: SSH, FTP, SMTP, and similar services send a
  greeting line the moment you connect, before you say anything — so
  this just connects and reads.
- **Active HTTP(S) probe**: HTTP/HTTPS servers wait for a request
  first, so this sends a minimal `HEAD /` request and reads back the
  response (particularly the `Server` header). Certificate
  verification is intentionally disabled for HTTPS, since the goal is
  identifying what's there, not establishing a trusted connection.

This stays strictly informational — a banner/version string, nothing
more. No automated vulnerability lookup or exploit code; that's a
deliberate line, not a missing feature (a future module may add known
*CVE* lookups against the grabbed version string, but that's a
separate, later piece of work).

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
