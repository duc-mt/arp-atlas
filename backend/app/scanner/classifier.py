"""
==============================================================================
Module Name:   classifier.py
Description:   Source module classifier.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 classifier.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

from backend.app.config import COMMON_PORTS


def _tcp_syn_scan(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Half-open (SYN) scan: send a bare SYN per port, record it as
    open on a SYN+ACK, then tear the attempt down ourselves with a RST
    before a full handshake ever completes - the same technique nmap's
    default privileged scan (`-sS`) uses. Lower overhead per port than
    `scan_device_ports`'s TCP-connect probe, and the target's own
    application never sees an established connection (so e.g. an HTTP
    or SSH access log never gets a line for it).

    Needs raw-socket privileges, same as the ARP sweep this tool
    already requires - no new privilege footprint for callers that
    already run the scanner as intended.
    """
    import scapy.all as scapy  # type: ignore[import-untyped]

    open_ports: list[int] = []
    for port in ports:
        syn = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")  # type: ignore[attr-defined]
        response = scapy.sr1(syn, timeout=timeout, verbose=False)
        if response is None or not response.haslayer(scapy.TCP):  # type: ignore[attr-defined]
            continue
        tcp_layer = response.getlayer(scapy.TCP)  # type: ignore[attr-defined]
        if tcp_layer is None or tcp_layer.flags != 0x12:  # SYN+ACK only - anything else isn't "open"
            continue
        open_ports.append(port)
        rst = scapy.IP(dst=ip) / scapy.TCP(  # type: ignore[attr-defined]
            dport=port, flags="R", seq=tcp_layer.ack
        )
        scapy.send(rst, verbose=False)
    return open_ports


def scan_device_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 0.3,
    method: str = "connect",
) -> list[int]:
    """Probe each port in `ports` and return the ones found open.

    Parameters
    ----------
    ip : str
        The IP address to probe.
    ports : list[int] or None
        Which ports to try. Defaults to COMMON_PORTS.
    timeout : float
        Seconds to wait for each probe.
    method : str
        "connect" (default) completes a full TCP handshake per port -
        no special privileges needed beyond a normal socket. "syn"
        does a half-open SYN probe instead (see `_tcp_syn_scan`) -
        needs the same raw-socket privileges as the ARP sweep.

    Returns
    -------
    list[int]
        The subset of `ports` that accepted a connection, in the
        order they were probed.
    """
    ports = COMMON_PORTS if ports is None else ports

    if method == "syn":
        return _tcp_syn_scan(ip, ports, timeout)

    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except OSError:
                pass
    return open_ports


def classify_device(vendor: str | None, open_ports: list[int]) -> str:
    """A rough, best-effort guess at a device's role from its vendor
    name and open ports.

    Parameters
    ----------
    vendor : str or None
        As returned by lookup_vendor().
    open_ports : list[int]
        As returned by scan_device_ports().

    Returns
    -------
    str
        One of the categorized roles or "unknown".
    """
    vendor_lower = (vendor or "").lower()
    ports = set(open_ports or [])

    scores: dict[str, int] = {
        "router/switch": 0,
        "access point": 0,
        "ip camera": 0,
        "smart home device": 0,
        "printer": 0,
        "windows host": 0,
        "linux host": 0,
        "server": 0,
        "web-enabled device": 0,
    }

    # Narrow, high-confidence Layer 4 signatures
    if 554 in ports or {8000, 37777, 34567} & ports:
        scores["ip camera"] += 5
    if {1883, 8883} & ports:
        scores["smart home device"] += 3
    if {9100, 515, 631} & ports:
        scores["printer"] += 5

    # Windows
    windows_hits = {135, 445, 3389} & ports
    if len(windows_hits) >= 2:
        scores["windows host"] += 4
    elif 3389 in windows_hits:
        scores["windows host"] += 3

    # Server
    server_ports = {3306, 5432, 21, 22, 25, 143}
    server_hits = server_ports & ports
    if len(server_hits) >= 2:
        scores["server"] += 4

    # SSH alone: weak, generic signal
    if 22 in ports and len(server_hits) < 2:
        scores["server"] += 1
        scores["linux host"] += 1

    # Catch-all web
    if {80, 443, 8080, 8443} & ports:
        scores["web-enabled device"] += 1

    # Vendor-based signals
    networking_vendors = ("cisco", "juniper", "mikrotik", "netgear", "tp-link", "asustek", "d-link")
    if any(keyword in vendor_lower for keyword in networking_vendors):
        if 23 in ports or 161 in ports:
            scores["router/switch"] += 5
        else:
            scores["router/switch"] += 2

    camera_vendors = ("hikvision", "dahua")
    if any(keyword in vendor_lower for keyword in camera_vendors):
        if {554, 8000, 37777, 34567} & ports:
            scores["ip camera"] += 5
        else:
            scores["ip camera"] += 2

    iot_vendors = ("espressif", "xiaomi", "lumi", "tuya", "sonoff")
    if any(keyword in vendor_lower for keyword in iot_vendors):
        scores["smart home device"] += 3

    ap_vendors = ("ubiquiti", "aruba")
    if any(keyword in vendor_lower for keyword in ap_vendors):
        if 23 not in ports:
            scores["access point"] += 4
        else:
            scores["router/switch"] += 2

    best_category = max(scores, key=scores.__getitem__)
    best_score = scores[best_category]

    if best_score == 0:
        return "unknown"

    # Guard against ties
    top_categories = [c for c, s in scores.items() if s == best_score]
    if len(top_categories) > 1:
        return "unknown"

    return best_category


def scan_devices_ports(
    devices: list[dict[str, Any]],
    ports: list[int] | None = None,
    timeout: float = 0.3,
    progress_callback: Any = None,
    method: str = "connect",
) -> list[dict[str, Any]]:
    """Add "open_ports" and "role" fields to each device dict in
    place, using scan_device_ports() and classify_device(), utilizing
    threads for speed.

    `method` is passed straight through to scan_device_ports() -
    "connect" (default) or "syn" (see there for what each does).
    """
    ports = COMMON_PORTS if ports is None else ports

    def _scan(device: dict[str, Any]) -> dict[str, Any]:
        open_ports = scan_device_ports(device["ip"], ports, timeout, method=method)
        device["open_ports"] = open_ports
        device["role"] = classify_device(device.get("vendor"), open_ports)
        return device

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_scan, d): d for d in devices}
        for count, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            device = future.result()
            if progress_callback:
                progress_callback(count, len(devices), device)
    return devices
