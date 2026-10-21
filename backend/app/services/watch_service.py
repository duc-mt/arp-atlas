"""
==============================================================================
Module Name:   watch_service.py
Description:   Change detection for `--watch` mode: compares a fresh scan with
               the previous one and the network's known-device registry, and
               returns the events worth alerting on.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         from backend.app.services.watch_service import detect_changes
Notes:         Requires Python 3.10+. Pure functions - no I/O.
==============================================================================
"""

from __future__ import annotations

import dataclasses
from typing import Any

NEW_DEVICE = "new_device"
MAC_CHANGED = "mac_changed"
GATEWAY_MAC_CHANGED = "gateway_mac_changed"


@dataclasses.dataclass(frozen=True)
class Alert:
    """One event worth telling the operator about."""

    kind: str
    ip: str
    mac: str
    detail: str


def detect_changes(
    previous_devices: list[dict[str, Any]],
    current_devices: list[dict[str, Any]],
    known_macs: set[str],
    gateway_ip: str | None = None,
) -> list[Alert]:
    """Events between the previous scan and this one.

    - `new_device`: a MAC that has never been seen on this network.
    - `mac_changed`: an IP that answered from a different MAC than in the
      previous scan - a DHCP re-lease, a replaced NIC, or ARP spoofing.
    - `gateway_mac_changed`: the same, for `gateway_ip`. Traffic to the
      gateway is what an ARP-spoofing attacker redirects, so this is the
      one to take seriously.

    The first scan of a network (nothing previous, nothing known) is just
    a baseline: it raises no alerts, rather than flagging every device
    as new.

    Parameters
    ----------
    known_macs : set[str]
        Lower-case MACs seen before this scan - see
        history_service.known_device_macs().
    """
    if not previous_devices and not known_macs:
        return []

    previous_mac_by_ip = {d["ip"]: str(d["mac"]).lower() for d in previous_devices}
    alerts: list[Alert] = []
    for device in current_devices:
        ip, mac = device["ip"], str(device["mac"]).lower()

        old_mac = previous_mac_by_ip.get(ip)
        if old_mac is not None and old_mac != mac:
            kind = GATEWAY_MAC_CHANGED if ip == gateway_ip else MAC_CHANGED
            alerts.append(Alert(kind, ip, mac, f"{ip} was {old_mac}, now answers from {mac}"))

        if mac not in known_macs:
            detail = "never seen on this network before"
            if device.get("is_randomized"):
                detail += " (randomized MAC - phones rotate these, so this may be a known device)"
            alerts.append(Alert(NEW_DEVICE, ip, mac, detail))
    return alerts
