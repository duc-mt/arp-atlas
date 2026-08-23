<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
# Table of Contents

- [Network Scanner](#network-scanner)
- [Requirements](#requirements)
- [Usage](#usage)
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

To use this project, you can run the script main.py from the command
line as root:

```bash
$ sudo python main.py
```

The script will ask you to enter the network address that you want to scan, such
as 192.168.1.0/24. The network address must be a valid IP address or network,
otherwise the script will raise an error. The script will then send ARP requests
to all devices on the network and capture the ARP responses. For each device
that responds, the script looks up its manufacturer (from the MAC address's
OUI) and attempts a reverse DNS lookup for its hostname, then prints the IP
address, MAC address, vendor, and hostname of every device that responded to
the ARP requests. If the same IP address answers from two different MAC
addresses, a warning is printed before the results.

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
reasoning): SNMP polling, persistence/baseline diffing ("what changed
since last scan"), a non-interactive CLI, and anything AI-adjacent -
all flagged as either heavier dependencies, bigger architectural
changes, or open-ended scope that didn't fit a small, single-file
project.

