"""
==============================================================================
Module Name:   conflict_service.py
Description:   Source module conflict_service.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 conflict_service.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import collections
from typing import Any


def find_ip_conflicts(devices: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Find any IP address that answered from more than one distinct
    MAC address in this scan.

    Two different MACs both claiming the same IP is the classic
    signature of either a misconfigured static IP, or an ARP-spoofing
    /man-in-the-middle attempt in progress.

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network().

    Returns
    -------
    dict[str, list[str]]
        Maps each conflicting IP to the sorted list of MAC addresses
        that answered for it. Empty if there are no conflicts.
    """
    macs_by_ip: dict[str, set[str]] = collections.defaultdict(set)
    for device in devices:
        macs_by_ip[device["ip"]].add(device["mac"])

    return {ip: sorted(macs) for ip, macs in macs_by_ip.items() if len(macs) > 1}
