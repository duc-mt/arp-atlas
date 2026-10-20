"""
==============================================================================
Module Name:   test_models.py
Description:   Tests for NetworkDevice: exact dict round trips, and that
               using it can't change what export_devices() writes.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_models.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import csv
import typing
from pathlib import Path

import pytest

from backend.app.models import NetworkDevice
from backend.app.services.export_service import export_devices

_SCANNED = {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}
_ENRICHED = {**_SCANNED, "vendor": "Cisco Systems", "hostname": "sw1", "is_randomized": False}
_PORT_SCANNED = {**_ENRICHED, "open_ports": [22, 443], "role": "server"}


@pytest.mark.parametrize(
    "device",
    [
        pytest.param(_SCANNED, id="arp-only"),
        pytest.param(_ENRICHED, id="enriched"),
        pytest.param(
            {**_SCANNED, "vendor": None, "hostname": None, "is_randomized": True},
            id="enriched-nothing-resolved",
        ),
        pytest.param(_PORT_SCANNED, id="port-scanned"),
        pytest.param({**_ENRICHED, "open_ports": [], "role": "unknown"}, id="nothing-open"),
        pytest.param({**_SCANNED, "vendor": "X", "hostname": "h"}, id="legacy-no-is_randomized"),
        pytest.param({**_PORT_SCANNED, "added_later": {"a": 1}}, id="unknown-key"),
    ],
)
def test_round_trip_is_exact(device: dict[str, typing.Any]) -> None:
    result = NetworkDevice.from_dict(device).to_dict()
    assert result == device
    assert set(result) == set(device)  # same keys present, not just equal values


class TestFromDict:
    def test_reads_every_field(self) -> None:
        d = NetworkDevice.from_dict(_PORT_SCANNED)
        assert (d.ip, d.mac) == ("192.168.1.1", "aa:aa:aa:aa:aa:aa")
        assert (d.vendor, d.hostname, d.is_randomized) == ("Cisco Systems", "sw1", False)
        assert (d.open_ports, d.role) == ([22, 443], "server")
        assert d.extra == {}

    def test_stage_fields_are_none_before_their_stage_runs(self) -> None:
        d = NetworkDevice.from_dict(_SCANNED)
        assert d.vendor is None
        assert d.is_randomized is None
        assert d.open_ports is None
        assert d.role is None

    def test_unknown_keys_land_in_extra(self) -> None:
        d = NetworkDevice.from_dict({**_SCANNED, "rtt_ms": 1.5})
        assert d.extra == {"rtt_ms": 1.5}

    def test_ip_and_mac_are_required(self) -> None:
        with pytest.raises(KeyError):
            NetworkDevice.from_dict({"ip": "192.168.1.1"})

    def test_does_not_alias_the_source_port_list(self) -> None:
        source = {**_PORT_SCANNED, "open_ports": [22]}
        d = NetworkDevice.from_dict(source)
        assert d.open_ports is not None
        d.open_ports.append(80)
        assert source["open_ports"] == [22]


class TestToDict:
    def test_a_bare_device_is_just_ip_and_mac(self) -> None:
        assert NetworkDevice("192.168.1.1", "aa:aa:aa:aa:aa:aa").to_dict() == _SCANNED

    def test_unset_stage_fields_stay_absent_rather_than_defaulting(self) -> None:
        keys = set(NetworkDevice("192.168.1.1", "aa:aa:aa:aa:aa:aa").to_dict())
        assert keys == {"ip", "mac"}  # in particular: no "role": "unknown"

    def test_constructed_with_values_emits_them(self) -> None:
        d = NetworkDevice("192.168.1.1", "aa:aa:aa:aa:aa:aa", open_ports=[80], role="printer")
        assert d.to_dict() == {**_SCANNED, "open_ports": [80], "role": "printer"}

    def test_an_empty_port_list_is_emitted(self) -> None:
        d = NetworkDevice("192.168.1.1", "aa:aa:aa:aa:aa:aa", open_ports=[], role="unknown")
        assert d.to_dict()["open_ports"] == []

    def test_returned_port_list_is_a_copy(self) -> None:
        d = NetworkDevice.from_dict(_PORT_SCANNED)
        d.to_dict()["open_ports"].append(8080)
        assert d.open_ports == [22, 443]


class TestExportCompatibility:
    """export_devices() adds the open_ports/role CSV columns iff some
    device dict has a "role" key. A model that always emitted
    role="unknown" would have added those columns to every export."""

    def _header(self, tmp_path: Path, devices: list[NetworkDevice]) -> list[str]:
        path = tmp_path / "out.csv"
        export_devices([d.to_dict() for d in devices], str(path))
        with open(path, newline="") as f:
            return next(csv.reader(f))

    def test_no_port_columns_when_nothing_was_port_scanned(self, tmp_path: Path) -> None:
        device = NetworkDevice.from_dict(_ENRICHED)
        assert self._header(tmp_path, [device]) == ["ip", "mac", "vendor", "hostname"]

    def test_port_columns_once_a_device_has_a_role(self, tmp_path: Path) -> None:
        device = NetworkDevice.from_dict(_PORT_SCANNED)
        assert self._header(tmp_path, [device]) == [
            "ip",
            "mac",
            "vendor",
            "hostname",
            "open_ports",
            "role",
        ]


def test_is_exported_from_the_public_api_shim() -> None:
    import backend.app.main as api

    assert api.NetworkDevice is NetworkDevice
    assert "NetworkDevice" in api.__all__
