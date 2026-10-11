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

# Well-known ports probed when --scan-ports is enabled
COMMON_PORTS = [22, 80, 443, 3389, 9100]

# Per-protocol timeout for hostname resolution (reverse DNS, mDNS, LLMNR,
# NBNS). Kept in the 0.4s-0.6s band: long enough for a real LAN device to
# answer, short enough that a handful of silent IPs don't stall a scan.
DEFAULT_HOSTNAME_TIMEOUT = 0.5

# Random delay range (seconds) between individual ARP requests in
# --gentle-scan mode, so a sweep doesn't burst all 254 requests on a /24
# at once - useful on switches/IDS tuned to flag that as a storm or a
# sweep. Only applies in gentle mode; the default scan is unaffected.
GENTLE_SCAN_JITTER = (0.01, 0.05)
