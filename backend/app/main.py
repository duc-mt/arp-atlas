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

from __future__ import annotations

from backend.app.config import COMMON_PORTS, DEFAULT_TIMEOUT, HISTORY_FILE
from backend.app.models import NetworkDevice
from backend.app.scanner.arp_scanner import scan_network, validate_network
from backend.app.scanner.classifier import (
    classify_device,
    classify_device_scored,
    parse_port_spec,
    scan_device_ports,
    scan_devices_ports,
)
from backend.app.scanner.port_scanner_async import (
    async_scan_devices_ports,
    scan_devices_ports_async,
)
from backend.app.server.server import run_dashboard
from backend.app.services.conflict_service import find_ip_conflicts
from backend.app.services.enrichment import enrich_devices, lookup_hostname, lookup_vendor
from backend.app.services.export_service import export_devices
from backend.app.services.history_service import (
    diff_devices,
    known_device_macs,
    load_history,
    save_scan,
)
from backend.app.services.network_utils import get_default_gateway
from backend.app.services.watch_service import Alert, detect_changes

__all__ = [
    "COMMON_PORTS",
    "DEFAULT_TIMEOUT",
    "HISTORY_FILE",
    "Alert",
    "NetworkDevice",
    "async_scan_devices_ports",
    "classify_device",
    "classify_device_scored",
    "detect_changes",
    "diff_devices",
    "enrich_devices",
    "export_devices",
    "find_ip_conflicts",
    "get_default_gateway",
    "known_device_macs",
    "load_history",
    "lookup_hostname",
    "lookup_vendor",
    "parse_port_spec",
    "run_dashboard",
    "save_scan",
    "scan_device_ports",
    "scan_devices_ports",
    "scan_devices_ports_async",
    "scan_network",
    "validate_network",
]
