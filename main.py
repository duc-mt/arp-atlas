"""
==============================================================================
Module Name:   main.py
Description:   Source module main.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 main.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from backend.app.config import COMMON_PORTS, DEFAULT_TIMEOUT, HISTORY_FILE
from backend.app.scanner.arp_scanner import scan_network, validate_network
from backend.app.scanner.classifier import classify_device, scan_device_ports, scan_devices_ports
from backend.app.services.conflict_service import find_ip_conflicts
from backend.app.services.enrichment import (
    _enrich_devices_async,
    _lookup_hostname_async,
    enrich_devices,
    is_mac_randomized,
    lookup_hostname,
    lookup_vendor,
)
from backend.app.services.export_service import export_devices
from backend.app.services.history_service import diff_devices, load_history, save_scan
from cli.arp_atlas_cli.formatters import print_conflicts, print_diff, print_error, print_results
from cli.arp_atlas_cli.main import (
    build_arg_parser,
    check_npcap_on_windows,
    main,
    run_cli,
    run_interactive,
)

if __name__ == "__main__":
    raise SystemExit(main())
