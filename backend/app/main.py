"""Backend package entry point — exposes top-level convenience imports."""

from __future__ import annotations

from backend.app.config import COMMON_PORTS, DEFAULT_TIMEOUT, HISTORY_FILE
from backend.app.scanner.arp_scanner import scan_network, validate_network
from backend.app.scanner.classifier import classify_device, scan_device_ports, scan_devices_ports
from backend.app.services.conflict_service import find_ip_conflicts
from backend.app.services.enrichment import enrich_devices, lookup_hostname, lookup_vendor
from backend.app.services.export_service import export_devices
from backend.app.services.history_service import diff_devices, load_history, save_scan
from backend.app.server.server import run_dashboard

__all__ = [
    "COMMON_PORTS",
    "DEFAULT_TIMEOUT",
    "HISTORY_FILE",
    "scan_network",
    "validate_network",
    "classify_device",
    "scan_device_ports",
    "scan_devices_ports",
    "find_ip_conflicts",
    "enrich_devices",
    "lookup_hostname",
    "lookup_vendor",
    "export_devices",
    "diff_devices",
    "load_history",
    "save_scan",
    "run_dashboard",
]
