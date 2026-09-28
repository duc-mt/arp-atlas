"""Shared constants and configuration for arp-atlas backend."""

from __future__ import annotations

# Default ARP timeout (seconds)
DEFAULT_TIMEOUT = 1.0

# Persistence file for scan history
HISTORY_FILE = "scan_history.json"

# Well-known ports probed when --scan-ports is enabled
COMMON_PORTS = [22, 80, 443, 3389, 9100]
