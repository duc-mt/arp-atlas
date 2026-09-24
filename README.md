# network-hunter
[![CI](https://github.com/duc-mt/network-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/duc-mt/network-hunter/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue)](https://pypi.org/project/network-hunter/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
# Table of Contents

- [Network Scanner](#network-scanner)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Command-line options](#command-line-options)
  - [Scan history and diffing](#scan-history-and-diffing)
- [Example](#example)
- [Testing](#testing)
- [Development](#development)
- [Known Limitations](#known-limitations)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Network Scanner

This project is a network scanner that can scan a local network and identify
the IP addresses and MAC addresses of all connected devices, enrich each one
with its manufacturer and (when available) hostname, and flag any IP address
that answers from more than one MAC address - the classic signature of an IP
conflict or ARP spoofing.

It uses the **scapy** library to send/receive the ARP requests (and its
bundled IEEE manufacturer database for vendor lookups, so no extra
dependency or network call is needed for that part). It uses the **rich**
module for colourised error output, and the standard library's
**ipaddress** and **socket** modules for address validation and reverse DNS.

# Requirements

To run this project, you will to install necessary depencies by:

```bash
$ pip install -r requirements.txt
```

The ipaddress and socket modules are included in the standard library of
Python 3.

# Usage

### Web Dashboard (`--dashboard`)
A zero-dependency, locally-hosted web interface powered by Python's built-in `http.server` and Tailwind CSS.
Features include:
- **Interface Selector:** Select your specific local network adapter (e.g. `en0`) to strictly bind ARP broadcasts.
- **Granular IPv4 Ranges:** Scan explicit bounds (e.g., `192.168.1.1` to `192.168.1.254`) rather than just raw CIDR blocks.
- **Analytics & Pie Charts:** Visual breakdown using Chart.js to show "Responded", "Other Interface" (via routing checks), and "No Response" metrics.
- **Available Addresses:** One-click modal to calculate mathematically free IP addresses based on the scan range, complete with "Copy to Clipboard" and "Export to CSV".
- **Real-time Live Refresh:** Automatically clears the DOM container between loads to display real-time fetched progress.

To launch:
```bash
sudo python main.py --dashboard
```
Navigate to `http://localhost:8080` in your web browser.



To use this project, you can run the script main.py from the command
line as root, either interactively:

```bash
$ sudo python main.py
```

...or non-interactively, for scripting and automation:

```bash
$ sudo python main.py --network 192.168.1.0/24
```

The network address must be a valid IP address or network, otherwise the
script will raise an error. The script will then send ARP requests to all
devices on the network and capture the ARP responses. For each device that
responds, the script looks up its manufacturer (from the MAC address's
OUI) and attempts a reverse DNS lookup for its hostname, then prints the
IP address, MAC address, vendor, and hostname of every device that
responded to the ARP requests. If the same IP address answers from two
different MAC addresses, a warning is printed before the results.

## Command-line options

Run `python main.py --help` for the full list. The main ones:

```bash
# Give a larger network more time to reply (default: 1 second)
$ sudo python main.py --network 10.0.0.0/16 --timeout 5

# Also probe a handful of common ports and guess each device's role -
# adds noticeable time per device, so this is opt-in
$ sudo python main.py --network 192.168.1.0/24 --scan-ports

# Export results (format inferred from the extension)
$ sudo python main.py --network 192.168.1.0/24 --output scan.csv
$ sudo python main.py --network 192.168.1.0/24 --output scan.json

# Use a custom history file, or skip history/diffing entirely
$ sudo python main.py --network 192.168.1.0/24 --history-file /var/lib/nethunter/history.json
$ sudo python main.py --network 192.168.1.0/24 --no-history
```

Running without `--network` starts the interactive prompt (the original
behaviour), which also asks whether to scan ports and offers to export
results at the end.

## Scan history and diffing

Every scan is automatically compared against the previous scan of the
*same* network (matched by MAC address, not IP - IP can change between
scans under DHCP, so a device isn't reported as "gone" just because DHCP
handed it a new address) and persisted for next time, in `scan_history.json`
by default:

```txt
New devices since last scan:
  + 192.168.1.42	de:ad:be:ef:00:01

Devices missing since last scan:
  - 192.168.1.7	11:22:33:44:55:66

Devices with a changed IP since last scan:
  ~ aa:bb:cc:dd:ee:ff	192.168.1.10 -> 192.168.1.15
```

Nothing is printed on the very first scan of a network (there's nothing
to compare against yet), or on any scan where nothing changed.

# Example

Here is an example of the output of the script:

```txt
Enter the network address (e.g., 192.168.1.0 or 192.168.1.0/24): 192.168.1.0/24

IP Address              MAC Address            Vendor                     Hostname
------------------------------------------------------------------------------------
192.168.1.1              9c:5a:6b:1e:4f:0c      Google, Inc.               router.local
192.168.1.2              4a:7c:9f:3b:2d:8e      -                          -
192.168.1.254             b8:27:eb:5c:1b:9d      Raspberry Pi Foundation    pi-hole.local
```

A vendor or hostname of `-` just means that lookup came back empty (an
unregistered/locally-administered MAC, or no PTR record) - both routine on
most networks, not an error.

# Testing

Install the dev dependencies and run the test suite:

```bash
pip install -r requirements-dev.txt
pytest
```

Sending real ARP packets needs root privileges and a real network, so
the tests never do that: `scapy.srp()` is mocked out everywhere, and
only the ordinary Python logic around it (address validation, result
parsing, output formatting, error handling) is under test.

# Development

CI runs on every pull request and push via GitHub Actions
(`.github/workflows/ci.yml`): linting (`ruff`), tests across Python
3.10-3.12, and `bandit` + `pip-audit` security scans. A weekly CodeQL
scan and Dependabot are also configured.

# Known Limitations

A round of review found and fixed several issues:

- **The old CI workflow never actually ran.** It lived at
  `.github/main.yml` - GitHub Actions only discovers workflows under
  `.github/workflows/`, so a file directly under `.github/` is
  invisible to it. Every push and PR silently had no CI at all.
- **A pasted address with surrounding whitespace was rejected.**
  `ipaddress.ip_network()` doesn't trim its input, so a trailing
  newline or leading space - a common paste artifact - made a
  perfectly valid address fail validation with a confusing "not a
  valid network address" error.
- **A host address with a prefix was rejected outright.** Typing
  `192.168.1.5/24` (a natural way to say "scan the subnet this host is
  on") failed with "has host bits set", even though the intent is
  unambiguous and scapy's own address expansion already normalises it
  down to the containing network correctly.
- **Running without root crashed with a raw traceback.** Scanning
  needs raw-socket access; without it, `scapy.srp()` raises
  `PermissionError`, which wasn't handled anywhere despite every other
  error case in the script getting a friendly message.
- **An empty scan result printed just a bare header row**, with
  nothing underneath and no indication that zero devices were found.

## New since the initial review: enrichment and anomaly detection

Three low-effort, high-value features from `ROADMAP.md`'s capability
analysis have been implemented:

- **MAC vendor lookup** (`lookup_vendor()`) - identifies the
  manufacturer of each discovered device from its MAC address's OUI,
  using scapy's own bundled IEEE database. No new dependency, no
  network call.
- **Hostname resolution** (`lookup_hostname()`) - a reverse DNS lookup
  per device, using the standard library only. Kept deliberately
  simple: lookups run serially with a short (0.3s default) per-lookup
  timeout, rather than in parallel. On a network with many silent
  hosts this adds a small amount of time to each scan; that tradeoff
  was chosen over adding concurrency (threads/asyncio) to keep the
  implementation small - worth revisiting if scan time on larger
  networks becomes a real complaint.
- **IP conflict / ARP anomaly detection** (`find_ip_conflicts()`) - if
  the same IP address answers from two different MAC addresses in one
  scan, a warning is printed before the results table. This is the
  classic signature of either a misconfigured static IP or an
  ARP-spoofing attempt in progress.

Deliberately **not** implemented here (see `ROADMAP.md` for the full
reasoning): SNMP polling and anything AI-adjacent - flagged as either
heavier dependencies or open-ended scope that didn't fit a small,
single-file project.

## New since then: export, configurable timeout, CLI mode, history/diff, port scan

Five more features, closing most of the remaining gap flagged in the
original architecture review and roadmap:

1. **CSV/JSON export** (`export_devices()`) - `--output scan.csv` or
   `--output scan.json` (or the interactive prompt's export step). Format
   is inferred from the extension, or set explicitly with `--format`. No
   new dependency - stdlib `csv`/`json`.
2. **Configurable scan timeout** (`--timeout`) - the timeout used to be
   hardcoded to 1 second regardless of network size, which the original
   review flagged directly: a `/16` got the same window as a `/24` and
   would systematically under-report, since `scapy.srp()`'s timeout is a
   single wait covering the whole sweep, not a per-host retry budget.
3. **A non-interactive CLI mode** (`--network`, plus every flag above) -
   see "Command-line options". `main.py` with no arguments still runs the
   original interactive prompt.
4. **Scan history and diffing** (`load_history()`/`save_scan()`/
   `diff_devices()`) - the biggest addition, and the one the roadmap
   called out as the dependency almost everything else builds on. Every
   scan is compared against the last scan of the same network and
   persisted for next time - see "Scan history and diffing" above.
   Devices are matched by MAC address specifically, not IP, since IP can
   change between scans under DHCP.
5. **An opt-in port scan and rough device-role guess**
   (`scan_device_ports()`/`classify_device()`) - `--scan-ports` probes a
   small, fixed set of well-known ports (22, 80, 443, 3389, 9100) on each
   device and labels it printer/router-switch/windows-host/server/
   web-enabled-device/unknown from the result plus its vendor name. This
   is a best-effort heuristic, not authoritative - it's meant to make a
   device list more skimmable, not to replace real fingerprinting. Opt-in
   specifically because of the added latency: at up to 5 ports per device
   and a real per-port connection timeout, this meaningfully slows down a
   scan of many devices, unlike everything else in this list.

