"""
==============================================================================
Module Name:   formatters.py
Description:   Implementation and logic for formatters.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 formatters.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""
"""Rich console formatters — print scan results, diffs and errors."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.theme import Theme


def print_results(devices: list[dict[str, Any]]) -> None:
    """Print a formatted table of scan results to stdout."""
    if not devices:
        print("\nNo devices found.")
        return
    show_ports = any("role" in device for device in devices)
    headers = ["IP Address", "MAC Address", "Vendor", "Hostname"]
    if show_ports:
        headers += ["Open Ports", "Role"]
    print("\n" + "\t\t".join(headers), end="\n" + "-" * 70 + "\n")
    for device in devices:
        vendor = device.get("vendor") or "-"
        hostname = device.get("hostname") or "-"
        mac_display = f"{device['mac']} (Random)" if device.get("is_randomized") else device["mac"]
        row = [device["ip"], mac_display, vendor, hostname]
        if show_ports:
            open_ports = device.get("open_ports") or []
            ports_str = (",".join(str(port) for port in open_ports) if open_ports else "-")
            row += [ports_str, device.get("role") or "-"]
        print("\t\t".join(row))


def print_conflicts(conflicts: dict[str, list[str]]) -> None:
    """Print a warning for each IP address that answered from more
    than one MAC address — see find_ip_conflicts().
    """
    for ip, macs in conflicts.items():
        print_error(
            f"WARNING: {ip} responded from multiple MAC addresses "
            f"({', '.join(macs)}) - possible IP conflict or ARP spoofing."
        )


def print_diff(diff: dict[str, list]) -> None:
    """Print a summary of what changed since the last scan."""
    if diff["new"]:
        print("\nNew devices since last scan:")
        for device in diff["new"]:
            print(f"  + {device['ip']}\t{device['mac']}")
    if diff["missing"]:
        print("\nDevices missing since last scan:")
        for device in diff["missing"]:
            print(f"  - {device['ip']}\t{device['mac']}")
    if diff["ip_changed"]:
        print("\nDevices with a changed IP since last scan:")
        for device, old_ip in diff["ip_changed"]:
            print(f"  ~ {device['mac']}\t{old_ip} -> {device['ip']}")


def print_error(message: str) -> None:
    """Print an error message in red using rich."""
    custom_theme = Theme({"danger": "red"})
    console = Console(theme=custom_theme)
    console.print(message, style="danger")
