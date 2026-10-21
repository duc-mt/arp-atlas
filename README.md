# ARP Atlas
[![CI](https://github.com/duc-mt/arp-atlas/actions/workflows/ci.yml/badge.svg)](https://github.com/duc-mt/arp-atlas/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue)](https://pypi.org/project/arp-atlas/)
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
- [Review History](#review-history)

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

To run this project, Python 3.10+ is required.

### Quick Start (Standalone Executable - No Python Required)

For offline environments or machines without Python installed:
1. Download the standalone executable from [GitHub Releases](https://github.com/duc-mt/arp-atlas/releases) under **Latest Build**:
   - `arp-atlas-windows-amd64.exe` (Windows 64-bit; requires [Npcap](https://npcap.com/))
   - `arp-atlas-linux-amd64` (Linux 64-bit; run with `sudo`)
2. Run directly:
   ```bash
   # Linux:
   sudo ./arp-atlas-linux-amd64 --network 192.168.1.0/24

   # Windows (Run Command Prompt as Administrator):
   arp-atlas-windows-amd64.exe --network 192.168.1.0/24
   ```

### Quick Start (Source / Developer)

The project includes smart automatic launchers that inspect your system, auto-create `.venv` if missing, install dependencies, and run the CLI or web dashboard:

```bash
# Universal Launcher (Linux / macOS / Windows / WSL):
./run                          # Interactive prompt
./run --dashboard              # Launch web dashboard
./run --network 10.0.0.0/24    # Non-interactive scan

# Or directly via Python:
python3 scripts/run.py         # Linux / macOS
python scripts\run.py          # Windows
```

### Running without `sudo` (Optional)

Because ARP scanning uses raw Layer-2 sockets (`scapy`), execution normally requires elevated privileges (`sudo`). To run as a standard user without `sudo`:

- **macOS (temporary until reboot):**
  ```bash
  sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
  ```
- **Linux (grant capability to virtual environment):**
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(pwd)/.venv/bin/python
  ```

### Manual Setup

If you prefer to set up your virtual environment manually:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

The `ipaddress` and `socket` modules are included in the standard library of Python 3.

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
./run --dashboard
```
Navigate to `http://localhost:8080` in your web browser.

To use this project, you can run the script from the command line as root (or standard user if configured above), either interactively:

```bash
$ ./run
```

...or non-interactively, for scripting and automation:

```bash
$ ./run --network 192.168.1.0/24
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

# Also probe common ports and guess each device's role -
# adds noticeable time per device, so this is opt-in
$ sudo python main.py --network 192.168.1.0/24 --scan-ports

# Choose the ports: a preset (common - the default - or quick) or your own list
$ sudo python main.py --network 192.168.1.0/24 --scan-ports --ports quick
$ sudo python main.py --network 192.168.1.0/24 --scan-ports --ports 22,80,8000-8010

# Re-send unanswered ARP requests more (or less) than the default once
$ sudo python main.py --network 192.168.1.0/24 --retries 2

# Keep watching: re-scan every 60 s and alert on new devices / MAC changes
$ sudo python main.py --network 192.168.1.0/24 --watch 60

# Also look for SNMP agents (UDP/161), or use the asyncio port scanner
$ sudo python main.py --network 192.168.1.0/24 --scan-ports --snmp-probe
$ sudo python main.py --network 192.168.1.0/24 --scan-ports --async-scan

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

# Architecture

```
arp-atlas/
├── backend/                Core scanning engine and HTTP server
│   └── app/
│       ├── config.py       Shared constants (DEFAULT_TIMEOUT, HISTORY_FILE, COMMON_PORTS, PORT_PRESETS, ...)
│       ├── models.py       NetworkDevice - typed view of a device dict with an exact dict round trip
│       ├── scanner/
│       │   ├── arp_scanner.py    validate_network() + scan_network() — Scapy ARP sweep
│       │   ├── classifier.py     scan_device_ports(), classify_device(), scan_devices_ports(),
│       │   │                     parse_port_spec(), snmp_probe()
│       │   └── port_scanner_async.py  asyncio TCP connect scanner with a socket cap
│       ├── services/
│       │   ├── enrichment.py     lookup_vendor() (OUI), lookup_hostname() (rDNS), enrich_devices()
│       │   ├── conflict_service.py  find_ip_conflicts() — ARP anomaly / spoofing detection
│       │   ├── history_service.py   load_history(), save_scan(), diff_devices(), known_device_macs()
│       │   ├── watch_service.py     detect_changes() — new device / MAC change alerts for --watch
│       │   ├── network_utils.py     get_default_gateway()
│       │   └── export_service.py    export_devices() — CSV / JSON output
│       └── server/
│           ├── handler.py    DashboardHandler — request guards, POST /api/scan, GET /api/status, GET /
│           └── server.py     run_dashboard() — TCP server entry point
│   └── tests/              Unit tests for all backend modules
├── cli/                    Command-line interface
│   └── arp_atlas_cli/
│       ├── main.py         build_arg_parser(), run_cli(), run_interactive(), main()
│       └── formatters.py   print_results(), print_diff(), print_conflicts(), print_error()
│   └── tests/              Unit tests for CLI and formatters
├── frontend/
│   └── dashboard.html      Single-file web dashboard (no build step)
├── scripts/
│   └── run-dashboard.sh    Convenience launcher (auto-elevates to sudo)
├── main.py                 Backward-compat shim — re-exports everything so
│                           `sudo python main.py` and `import main` still work
└── dashboard.py            Backward-compat shim — re-exports run_dashboard
```

**Data flow (CLI scan)**:
`main()` → `validate_network()` → `scan_network()` (Scapy ARP broadcast, needs root)
→ `find_ip_conflicts()` → `enrich_devices()` (OUI lookup + async rDNS, no root needed)
→ optionally `scan_devices_ports()` + `classify_device()` (TCP connect, opt-in)
→ `print_results()` / JSON-lines stdout → `diff_devices()` against history → `save_scan()`.

**Data flow (dashboard)**:
Browser → `POST /api/scan` → same pipeline above, result persisted to `scan_history.json`
→ browser polls `GET /scan_history.json` to render the table.

**Why root is required**: `scapy.srp()` opens a raw Layer-2 socket to send and capture
ARP frames. Everything downstream — vendor lookup, rDNS, port scan, history, export —
runs as normal Python and needs no elevated privileges.

**Why a single `dashboard.html`**: the dashboard has no build step and no npm dependency.
All interactivity is vanilla JS + a small amount of inline CSS. Scapy injects the
interface `<option>` list server-side on each `GET /`; everything else is fetched via
`fetch()` from the running Python server.

---

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

# Review History

(Previously titled "Known Limitations," which read as a list of open
problems - every item below, including the two address-parsing bugs, is
already fixed; see `validate_network()` in
`backend/app/scanner/arp_scanner.py` and
`backend/tests/test_validate_network.py`.)

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
   (`scan_device_ports()`/`classify_device()`) - `--scan-ports` originally
   probed a small, fixed set of well-known ports (22, 80, 443, 3389, 9100) on
   each device (see "Port scan coverage and options" below for today's list) and labels it printer/router-switch/windows-host/server/
   web-enabled-device/unknown from the result plus its vendor name. This
   is a best-effort heuristic, not authoritative - it's meant to make a
   device list more skimmable, not to replace real fingerprinting. Opt-in
   specifically because of the added latency: at up to 5 ports per device
   and a real per-port connection timeout, this meaningfully slows down a
   scan of many devices, unlike everything else in this list.

## New since then: fresher vendor data + multi-protocol hostname resolution

Both of `enrich_devices()`'s fields had a quiet failure mode that showed up
as a plain "-" in the dashboard far more often than it should have:

- **Vendor lookups only knew what scapy shipped with.**
  `scapy.conf.manufdb` is a bundled snapshot of the IEEE registry, only
  refreshed when scapy itself is upgraded - any OUI allocated since then
  (e.g. `10:5F:02`, registered to Ruijie Networks in 2022) came back as a
  miss indistinguishable from "not a real OUI". `lookup_vendor()` now
  checks a small cached copy of Wireshark's own `manuf` database first
  (`backend/app/data/manuf.gz`, loaded once per process) and only falls
  back to scapy's bundled database if that also misses - no new runtime
  dependency, no network call on the hot path. Run
  `scripts/update-manuf-db.sh` (needs network access) whenever you want
  to refresh that cache from Wireshark's upstream file - or let
  `.github/workflows/update-oui.yml` do it: on the 1st of every month (and
  on demand from the Actions tab) it runs the script, and only if the
  decompressed database actually changed it runs the test suite and opens
  (or updates) a pull request on the `chore/update-oui-db` branch. Started by
  hand with `mode=commit` it pushes to the default branch instead. It needs
  "Allow GitHub Actions to create and approve pull requests" enabled in the
  repository's Actions settings. The script refuses a download that isn't a
  real manuf file (fewer than 1000 OUI lines, or no Wireshark header),
  writes atomically, and gzips deterministically so an unchanged database
  never shows up as a diff.
- **Hostname resolution only tried unicast reverse DNS.** That depends on
  the LAN's DNS server having a PTR record for every DHCP lease, which
  most home/office networks never configure - so it silently resolved
  almost nothing. `lookup_hostname()` now races reverse DNS, mDNS
  (`224.0.0.251:5353` - Apple/Linux/Avahi/IoT/printers), LLMNR
  (`224.0.0.252:5355` - Windows), and NBNS (`UDP/137` NBSTAT - Windows,
  Samba/NAS shares) concurrently for each IP and takes whichever answers
  first, each bounded by a 0.4-0.6s per-protocol timeout so a handful of
  silent devices can't stall a scan.

## New since then: a gentler ARP sweep and a SYN port-scan option

Two opt-in flags for networks that are sensitive to how a scan looks on the
wire - a lab reproducing what a detection rule should catch, or production
switches tuned to flag either pattern:

- **`--gentle-scan`** (`scan_network(..., gentle=True)`) probes hosts one at
  a time, in randomized order, with a small random delay between each
  (`GENTLE_SCAN_JITTER` in `config.py`), instead of the default single
  broadcast covering the whole range. Avoids putting 254 ARP requests on the
  wire at once. The requests are paced by the jitter alone while a single
  background sniffer collects the replies, so a sweep takes about the sum of
  the jitters plus one `timeout` (an earlier version waited a full `timeout`
  after every request).
- **`--syn-scan`** (`scan_device_ports(..., method="syn")`) does a half-open
  TCP SYN probe instead of a full `connect()` - all of a host's ports go out
  in one batch, so a host that drops packets costs one `timeout`, not one per
  port - - the same technique
  nmap's default privileged scan uses: send a SYN, and on a SYN+ACK tear the
  attempt down ourselves with a RST before the handshake ever completes. Only
  takes effect alongside `--scan-ports`; needs the same raw-socket privileges
  the ARP sweep already requires.

Deliberately **not** included, regardless of framing: decoy/spoofed source
IPs, or anything else whose purpose is hiding which host is doing the
scanning. Both flags above change *how* this tool's own traffic looks -
they don't disguise who's sending it.

## Port scan coverage and options

`--scan-ports` used to probe only five ports (22, 80, 443, 3389, 9100), but
`classify_device()` also keys on telnet, SMB/RPC, the printer protocols, RTSP
and the camera vendors' proprietary ports, MQTT, and the usual
database/mail/FTP ports. A port the classifier looks for but the scan never
probes is a rule that can never fire, so most of the role guesses (camera,
smart-home, router/switch via telnet, most servers) were unreachable.

- **Default ports** (`COMMON_PORTS` in `config.py`) now cover every TCP port
  the classifier uses - 23 ports. That is several times more probes per device
  than before; for the old speed use **`--ports quick`** (the original five),
  or **`--ports 22,80,8000-8010`** for your own list (comma-separated ports
  and inclusive ranges; invalid input fails before the ARP sweep starts).
- **`--snmp-probe`** - SNMP is UDP/161, which a TCP probe can never find (the
  classifier's `161` rule was dead code). This sends one SNMPv2c GET for
  `sysDescr.0` with community `public`; a device that answers gets `161` in
  `open_ports` (here `161` means UDP). Agents configured with another
  community stay silent, so a miss doesn't prove SNMP is off.
- **`--async-scan`** - runs the TCP connect scan on an event loop
  (`port_scanner_async.py`) with a hard cap on concurrently open sockets
  (`ASYNC_FD_CAP`) and on devices in flight (`ASYNC_HOST_CONCURRENCY`). Same
  results as the thread pool. TCP connect only, so it can't be combined with
  `--syn-scan`. The thread pool is capped by `MAX_SCAN_WORKERS` (50); since
  each device's ports are probed one at a time, that is also the most sockets
  it holds open.
- `--ports`, `--snmp-probe` and `--async-scan` all require `--scan-ports`.

Also: `enrich_devices()` now works when called from a thread that already has
a running event loop (it used to raise `RuntimeError`), and
`backend.app.models.NetworkDevice` is available as an opt-in typed view of a
device dict - `NetworkDevice.from_dict(d).to_dict() == d` for anything the
pipeline produces, so adopting it can't change an export or a history file.

## Scan speed, dashboard hardening and watch mode

**Faster scans**

- **`--gentle-scan`** no longer blocks for a full `--timeout` after every
  request - see above. Measured on loopback against a fake responder, a
  10-host sweep dropped from about 4.2 s to 0.75 s, and the gap grows with
  the number of hosts.
- **`--syn-scan`** sends every port of a host in one `sr()` batch instead of
  one `sr1()` per port (23 default ports: about 0.27 s to 0.03 s on
  loopback; against a host that silently drops packets it is one timeout
  instead of 23).
- **`--retries N`** (default 1, max 5; `--retries 0` for the old single shot)
  re-sends ARP requests that got no answer. One shot loses replies on busy
  Wi-Fi and from sleeping IoT devices. Each retry costs one more `--timeout`
  window while hosts are still unanswered. Gentle mode ignores it.

**Role guesses use the hostname.** `classify_device(vendor, ports, hostname)`
treats a name like `ESP_1A2B3C`, `DESKTOP-AB12CD3`, `BRN30055C1234`,
`ipcam-front`, `AP-Lobby` or `SW-ACCESS-01` as a hint worth 3 points - enough
to settle a tie or a weak guess, never enough to outweigh a strong port
signature (5). `classify_device_scored()` also returns the winning score.
The score is not stored in the device dict, so exports and history are
unchanged.

**`--watch SECONDS`** (minimum 5) re-scans until Ctrl-C and alerts on:

- a MAC never seen before on this network (`NEW DEVICE`; randomized MACs are
  labelled as such, since phones rotate them),
- an address that now answers from a different MAC (`MAC CHANGED`), and
- the same for the default gateway (`GATEWAY MAC CHANGED`) - the classic sign
  of ARP spoofing.

The first scan only records a baseline. It needs scan history (so it can't be
combined with `--no-history`, `--output` or `--stream-jsonl`). History now
also keeps a `known_devices` registry per network (MAC to `first_seen` /
`last_seen`) that survives a device being switched off for one scan; the
device dicts themselves are unchanged.

**Dashboard**

- `POST /api/scan` and `POST /api/clear` act as whoever started the dashboard
  (often root), so they now refuse requests that did not come from the page
  itself: a browser `Origin` or `Sec-Fetch-Site` that isn't this server, a
  `Host` other than `127.0.0.1` / `localhost` / `[::1]` (DNS rebinding), and a
  scan body that isn't `application/json`. `curl` and scripts, which send no
  `Origin`, still work.
- The server is threaded. Only one scan runs at a time: a second one gets a
  `409`, and `GET /api/status` reports the current phase (ARP sweep,
  enriching, port scan with `done/total`, saving), which the Scan button
  shows while it runs.
- An **Options** panel exposes `--ports`, `--snmp-probe`, gentle mode,
  timeout and retries. Interface names are HTML-escaped.

**Tests and CI.** `backend/tests/test_raw_socket_integration.py` exercises the
ARP sweeps and the SYN scan over loopback with real raw sockets (it skips
itself without root / `CAP_NET_RAW`, e.g. on CI). CI now also runs
`ruff format --check .`.

`backend/tests/test_server.py` covers `run_dashboard()`: which address and
port it binds (loopback only), that it serves requests, and that Ctrl-C (a
real `SIGINT`) and `shutdown()` stop it and release the port - every test
that starts a server is time-bounded so a regression can't hang the suite.
`backend/tests/test_update_manuf_script.py` runs the OUI update script against
`file://` sources, and `backend/tests/test_repo_config.py` guards the
workflow wiring, unpinned (`>=`) dev dependencies and the ruff/mypy ignore
lists. The old root-level `tests/` directory is gone; the suite lives in
`backend/tests` and `cli/tests`.
