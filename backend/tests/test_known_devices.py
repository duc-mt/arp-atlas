"""
==============================================================================
Module Name:   test_known_devices.py
Description:   Tests for the per-network known-device registry that
               save_scan() keeps (first_seen / last_seen per MAC).
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_known_devices.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from backend.app.services.history_service import (
    known_device_macs,
    load_history,
    save_scan,
)

_NET = "192.168.1.0/24"
_A = {"ip": "192.168.1.10", "mac": "AA:AA:AA:AA:AA:AA"}
_B = {"ip": "192.168.1.20", "mac": "bb:bb:bb:bb:bb:bb"}


def _scan_at(path: Path, when: str, devices: list[dict]) -> None:
    fake_now = mock.Mock()
    fake_now.isoformat.return_value = when
    with mock.patch("backend.app.services.history_service.datetime.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        save_scan(str(path), _NET, devices)


def test_registry_records_first_and_last_seen(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    _scan_at(history, "2026-10-01T10:00:00+00:00", [_A])

    registry = load_history(str(history))[_NET]["known_devices"]
    assert registry == {
        "aa:aa:aa:aa:aa:aa": {
            "first_seen": "2026-10-01T10:00:00+00:00",
            "last_seen": "2026-10-01T10:00:00+00:00",
        }
    }


def test_a_returning_device_keeps_its_first_seen(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    _scan_at(history, "2026-10-01T10:00:00+00:00", [_A])
    _scan_at(history, "2026-10-02T10:00:00+00:00", [_A])

    entry = load_history(str(history))[_NET]["known_devices"]["aa:aa:aa:aa:aa:aa"]
    assert entry == {
        "first_seen": "2026-10-01T10:00:00+00:00",
        "last_seen": "2026-10-02T10:00:00+00:00",
    }


def test_a_device_missing_from_a_scan_stays_known(tmp_path: Path) -> None:
    """The registry outlives a single scan: a laptop that was off for one
    sweep must not look brand new when it comes back."""
    history = tmp_path / "h.json"
    _scan_at(history, "2026-10-01T10:00:00+00:00", [_A, _B])
    _scan_at(history, "2026-10-02T10:00:00+00:00", [_A])  # B is off
    _scan_at(history, "2026-10-03T10:00:00+00:00", [_A, _B])  # B is back

    entry = load_history(str(history))[_NET]
    assert entry["devices"] == [_A, _B]  # the scan itself is unchanged
    assert entry["known_devices"]["bb:bb:bb:bb:bb:bb"] == {
        "first_seen": "2026-10-01T10:00:00+00:00",
        "last_seen": "2026-10-03T10:00:00+00:00",
    }


def test_macs_are_matched_case_insensitively(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    _scan_at(history, "2026-10-01T10:00:00+00:00", [_A])
    _scan_at(history, "2026-10-02T10:00:00+00:00", [{**_A, "mac": _A["mac"].lower()}])

    assert len(load_history(str(history))[_NET]["known_devices"]) == 1


def test_device_dicts_are_stored_exactly_as_given(tmp_path: Path) -> None:
    """first/last_seen live in the registry, not on the devices, so
    exports, diffs and the dashboard see the same device dicts as before."""
    history = tmp_path / "h.json"
    device = {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa", "vendor": "X"}
    save_scan(str(history), _NET, [device])

    assert load_history(str(history))[_NET]["devices"] == [device]
    assert set(device) == {"ip", "mac", "vendor"}  # the caller's dict wasn't mutated


def test_history_written_before_the_registry_existed_is_seeded(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    history.write_text(
        json.dumps({_NET: {"timestamp": "2026-09-01T00:00:00+00:00", "devices": [_A]}})
    )
    _scan_at(history, "2026-10-01T10:00:00+00:00", [_A, _B])

    registry = load_history(str(history))[_NET]["known_devices"]
    assert registry["aa:aa:aa:aa:aa:aa"] == {
        "first_seen": "2026-09-01T00:00:00+00:00",  # earliest moment known
        "last_seen": "2026-10-01T10:00:00+00:00",
    }
    assert registry["bb:bb:bb:bb:bb:bb"]["first_seen"] == "2026-10-01T10:00:00+00:00"


def test_each_network_has_its_own_registry(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    save_scan(str(history), "10.0.0.0/24", [_A])
    save_scan(str(history), "10.1.0.0/24", [_B])

    data = load_history(str(history))
    assert set(data["10.0.0.0/24"]["known_devices"]) == {"aa:aa:aa:aa:aa:aa"}
    assert set(data["10.1.0.0/24"]["known_devices"]) == {"bb:bb:bb:bb:bb:bb"}


def test_devices_without_a_mac_are_skipped(tmp_path: Path) -> None:
    history = tmp_path / "h.json"
    save_scan(str(history), _NET, [{"ip": "192.168.1.9"}, _A])

    assert set(load_history(str(history))[_NET]["known_devices"]) == {"aa:aa:aa:aa:aa:aa"}


class TestKnownDeviceMacs:
    def test_never_scanned_network_knows_nothing(self) -> None:
        assert known_device_macs(None) == set()

    def test_reads_the_registry(self) -> None:
        entry = {
            "devices": [_A],
            "known_devices": {"aa:aa:aa:aa:aa:aa": {}, "cc:cc:cc:cc:cc:cc": {}},
        }
        assert known_device_macs(entry) == {"aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"}

    def test_falls_back_to_the_last_scan_for_old_history(self) -> None:
        assert known_device_macs({"devices": [_A, _B]}) == {
            "aa:aa:aa:aa:aa:aa",
            "bb:bb:bb:bb:bb:bb",
        }
