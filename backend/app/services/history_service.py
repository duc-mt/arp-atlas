"""
==============================================================================
Module Name:   history_service.py
Description:   Source module history_service.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 history_service.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import contextlib
import datetime
import json
import logging
import os
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


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
            data = json.load(f)
    except (OSError, ValueError):  # unreadable, not JSON, or not UTF-8
        return {}

    # Valid JSON of the wrong shape (a list, null, an entry that is a string,
    # devices that aren't dicts) would crash every caller with an
    # AttributeError or TypeError, so keep only well-formed entries - the same
    # way an unparseable file is treated as empty.
    if not isinstance(data, dict):
        logger.warning("ignoring %s: expected a JSON object, found %s", path, type(data).__name__)
        return {}
    valid: dict[str, Any] = {}
    for network, entry in data.items():
        devices = entry.get("devices") if isinstance(entry, dict) else None
        if isinstance(devices, list) and all(isinstance(d, dict) for d in devices):
            valid[network] = entry
        else:
            logger.warning("ignoring malformed history entry for %r in %s", network, path)
    return valid


def _mac_key(mac: Any) -> str:
    return str(mac).lower()


def known_device_macs(entry: dict[str, Any] | None) -> set[str]:
    """Every MAC ever recorded for a network, from its history entry.

    Uses the `known_devices` registry, which outlives a device's absence
    from any single scan. A history file written before the registry
    existed only has the last scan's devices, so those stand in. Returns
    an empty set for a network that has never been scanned (entry None).
    """
    if not entry:
        return set()
    registry = entry.get("known_devices")
    if registry is not None:
        return set(registry)
    return {_mac_key(d["mac"]) for d in entry.get("devices", []) if d.get("mac")}


def _update_known_devices(
    previous_entry: dict[str, Any] | None,
    devices: list[dict[str, Any]],
    now: str,
) -> dict[str, dict[str, str]]:
    """The registry of MAC -> {first_seen, last_seen} after a scan.

    Carries forward every MAC seen before (a device that was off during
    this scan keeps its first_seen, so it isn't "new" when it returns),
    and stamps last_seen on the ones present now. For an entry that
    predates the registry, the previous scan's devices are seeded with
    that scan's timestamp - the earliest moment known for them.
    """
    known: dict[str, dict[str, str]] = {}
    if previous_entry:
        existing = previous_entry.get("known_devices")
        if existing is not None:
            known = {mac: dict(times) for mac, times in existing.items()}
        else:
            seeded_at = previous_entry.get("timestamp") or now
            for device in previous_entry.get("devices", []):
                if device.get("mac"):
                    known[_mac_key(device["mac"])] = {
                        "first_seen": seeded_at,
                        "last_seen": seeded_at,
                    }
    for device in devices:
        if not device.get("mac"):
            continue
        entry = known.setdefault(_mac_key(device["mac"]), {"first_seen": now, "last_seen": now})
        entry["last_seen"] = now
    return known


def save_scan(
    path: str,
    network: str,
    devices: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
) -> None:
    """Persist `devices` as the new most-recent scan for `network`,
    leaving any other network's entry in the history file untouched.

    Alongside the devices, the entry keeps a `known_devices` registry
    (MAC -> first_seen/last_seen) that survives a device being absent
    from a scan - see known_device_macs().

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
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    history[network] = {
        "timestamp": now,
        "devices": devices,
        "known_devices": _update_known_devices(history.get(network), devices, now),
    }
    if stats:
        history[network]["stats"] = stats

    # Write to a temp file in the same directory and atomically rename it
    # into place, rather than writing `path` directly. A crash or power
    # loss mid-write (or two scans racing) can otherwise leave a
    # truncated/corrupt JSON file - and load_history() treats any
    # unparseable file as "no history", silently discarding every past
    # scan, not just the one in progress.
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(history, f, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise


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
