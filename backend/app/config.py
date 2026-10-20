"""
==============================================================================
Module Name:   config.py
Description:   Source module config.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 config.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

# Default ARP timeout (seconds)
DEFAULT_TIMEOUT = 1.0

# Persistence file for scan history
HISTORY_FILE = "scan_history.json"

# Well-known TCP ports probed when --scan-ports is enabled. Deliberately
# covers every port classifier.classify_device() keys on (telnet, SMB/RPC,
# printer protocols, RTSP and the camera vendors' proprietary ports, MQTT,
# common database/mail/FTP ports, alternate web ports) - a port the
# classifier looks for but the scan never probes is a rule that can never
# fire. SNMP (161) is UDP, so it is not in this list; see SNMP_PORT.
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    80,
    135,
    143,
    443,
    445,
    515,
    554,
    631,
    1883,
    3306,
    3389,
    5432,
    8000,
    8080,
    8443,
    8883,
    9100,
    34567,
    37777,
]

# The original five-port set - several times faster per device. Select it
# with `--ports quick`.
QUICK_PORTS = [22, 80, 443, 3389, 9100]

# Names accepted by `--ports` (and classifier.parse_port_spec()).
PORT_PRESETS = {"quick": QUICK_PORTS, "common": COMMON_PORTS}

# SNMP listens on UDP/161, which a TCP connect or SYN probe can never find.
# With --snmp-probe a UDP SNMP GET is sent instead, and 161 is added to a
# device's open_ports when an agent answers.
SNMP_PORT = 161

# Upper bound on devices scanned in parallel by the threaded port scanner.
# Ports are probed one at a time per device, so this is also the most TCP
# sockets (or scapy sessions) the scan holds open at once.
MAX_SCAN_WORKERS = 50

# Async port scanner (--async-scan): hard cap on concurrently open sockets
# across all devices, and on devices in flight at once.
ASYNC_FD_CAP = 256
ASYNC_HOST_CONCURRENCY = 64

# Per-protocol timeout for hostname resolution (reverse DNS, mDNS, LLMNR,
# NBNS). Kept in the 0.4s-0.6s band: long enough for a real LAN device to
# answer, short enough that a handful of silent IPs don't stall a scan.
DEFAULT_HOSTNAME_TIMEOUT = 0.5

# Random delay range (seconds) between individual ARP requests in
# --gentle-scan mode, so a sweep doesn't burst all 254 requests on a /24
# at once - useful on switches/IDS tuned to flag that as a storm or a
# sweep. Only applies in gentle mode; the default scan is unaffected.
GENTLE_SCAN_JITTER = (0.01, 0.05)
