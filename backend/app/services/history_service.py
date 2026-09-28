"""Scan history persistence and device diff utilities."""

from __future__ import annotations

import datetime
import json
import typing
from typing import Any


def load_history(path: str) -> dict[str, Any]:
    """Load previously-persisted scan results, keyed by the exact
    network string that was scanned.

    Returns
    -------
    dict[str, dict]
        Maps network -> {"timestamp": ISO 8601 str, "devices": [...]}.
        Empty if the file doesn't exist yet or isn't valid JSON.
    """
    try:
        with open(path) as f:
            return typing.cast(dict[str, Any], json.load(f))
    except (OSError, json.JSONDecodeError):
        return {}


def save_scan(
    path: str,
    network: str,
    devices: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
) -> None:
    """Persist `devices` as the new most-recent scan for `network`,
    leaving any other network's entry in the history file untouched.

    Parameters
    ----------
    path : str
        Path to the history file.
    network : str
        The network that was scanned — the key this scan is stored under.
    devices : list[dict]
        The (ideally enriched) scan results to persist.
    stats : dict | None
        Optional scan statistics (responded, no_response, wrong_iface).
    """
    history = load_history(path)
    history[network] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "devices": devices,
    }
    if stats:
        history[network]["stats"] = stats
    with open(path, "w") as f:
        json.dump(history, f, indent=2)


def diff_devices(
    previous_devices: list[dict[str, Any]],
    current_devices: list[dict[str, Any]],
) -> dict[str, list]:
    """Compare two device lists by MAC address and report what changed.

    A device's MAC is a far more stable identifier than its IP, which
    can easily change between scans under DHCP.

    Returns
    -------
    dict
        "new": devices present now but not before.
        "missing": devices present before but not now.
        "ip_changed": (device, old_ip) pairs for devices whose MAC
        matches a previous scan but whose IP has changed.
    """
    previous_by_mac = {d["mac"]: d for d in previous_devices}
    current_by_mac = {d["mac"]: d for d in current_devices}

    new = [d for mac, d in current_by_mac.items() if mac not in previous_by_mac]
    missing = [d for mac, d in previous_by_mac.items() if mac not in current_by_mac]
    ip_changed = [
        (current_by_mac[mac], previous_by_mac[mac]["ip"])
        for mac in current_by_mac
        if mac in previous_by_mac and current_by_mac[mac]["ip"] != previous_by_mac[mac]["ip"]
    ]

    return {"new": new, "missing": missing, "ip_changed": ip_changed}
