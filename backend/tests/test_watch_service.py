"""
==============================================================================
Module Name:   test_watch_service.py
Description:   Tests for watch-mode change detection.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_watch_service.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

from backend.app.services.watch_service import (
    GATEWAY_MAC_CHANGED,
    MAC_CHANGED,
    NEW_DEVICE,
    Alert,
    detect_changes,
)

_GW = {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01"}
_PC = {"ip": "192.168.1.20", "mac": "aa:aa:aa:aa:aa:20"}
_KNOWN = {"aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:20"}


def _kinds(alerts: list[Alert]) -> list[str]:
    return [a.kind for a in alerts]


def test_first_scan_is_a_baseline_and_raises_nothing() -> None:
    assert detect_changes([], [_GW, _PC], set(), gateway_ip="192.168.1.1") == []


def test_an_unchanged_network_is_quiet() -> None:
    assert detect_changes([_GW, _PC], [_GW, _PC], _KNOWN, "192.168.1.1") == []


def test_a_never_seen_mac_is_a_new_device() -> None:
    stranger = {"ip": "192.168.1.99", "mac": "de:ad:be:ef:00:99"}
    alerts = detect_changes([_GW, _PC], [_GW, _PC, stranger], _KNOWN)

    assert alerts == [
        Alert(NEW_DEVICE, "192.168.1.99", "de:ad:be:ef:00:99", "never seen on this network before")
    ]


def test_a_device_that_was_only_off_is_not_new() -> None:
    """Absent from the previous scan but in the registry => not an alert."""
    assert detect_changes([_GW], [_GW, _PC], _KNOWN) == []


def test_a_randomized_mac_is_flagged_as_such() -> None:
    phone = {"ip": "192.168.1.50", "mac": "02:11:22:33:44:55", "is_randomized": True}
    (alert,) = detect_changes([_GW], [_GW, phone], {"aa:aa:aa:aa:aa:01"})

    assert alert.kind == NEW_DEVICE
    assert "randomized MAC" in alert.detail


def test_an_address_answering_from_a_new_mac_is_a_mac_change() -> None:
    swapped = {"ip": _PC["ip"], "mac": "aa:aa:aa:aa:aa:77"}
    alerts = detect_changes([_GW, _PC], [_GW, swapped], _KNOWN)

    assert _kinds(alerts) == [MAC_CHANGED, NEW_DEVICE]
    change = alerts[0]
    assert change.ip == "192.168.1.20"
    assert change.mac == "aa:aa:aa:aa:aa:77"
    assert "aa:aa:aa:aa:aa:20" in change.detail


def test_a_mac_change_on_the_gateway_is_called_out() -> None:
    """Redirecting the gateway's address is what an ARP spoofer does."""
    spoofed = {"ip": "192.168.1.1", "mac": "de:ad:be:ef:00:01"}
    alerts = detect_changes([_GW, _PC], [spoofed, _PC], _KNOWN, gateway_ip="192.168.1.1")

    assert GATEWAY_MAC_CHANGED in _kinds(alerts)
    assert MAC_CHANGED not in _kinds(alerts)


def test_without_a_known_gateway_it_is_a_plain_mac_change() -> None:
    spoofed = {"ip": "192.168.1.1", "mac": "de:ad:be:ef:00:01"}
    alerts = detect_changes([_GW], [spoofed], _KNOWN, gateway_ip=None)

    assert MAC_CHANGED in _kinds(alerts)


def test_mac_comparison_ignores_case() -> None:
    upper = {"ip": "192.168.1.20", "mac": "AA:AA:AA:AA:AA:20"}
    assert detect_changes([_PC], [upper], _KNOWN) == []


def test_a_device_that_disappears_is_not_an_alert() -> None:
    assert detect_changes([_GW, _PC], [_GW], _KNOWN) == []
