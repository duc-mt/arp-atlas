
"""
==============================================================================
Module Name:   config.py
Description:   Shared constants and configuration for arp-atlas backend.
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
