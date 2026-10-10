"""
==============================================================================
Module Name:   test_enrich_devices.py
Description:   Source module test_enrich_devices.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_enrich_devices.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import typing
from unittest import mock

from backend.app.services.enrichment import enrich_devices


class TestEnrichDevices:
    def test_adds_vendor_and_hostname_to_each_device(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]

        with (
            mock.patch(
                "backend.app.services.enrichment.lookup_vendor", side_effect=["Vendor A", None]
            ),
            mock.patch(
                "backend.app.services.enrichment._lookup_hostname_async",
                side_effect=[None, "host-b.local"],
            ),
        ):
            result = enrich_devices(devices)

        assert result[0]["vendor"] == "Vendor A"
        assert result[0]["hostname"] is None
        assert result[1]["vendor"] is None
        assert result[1]["hostname"] == "host-b.local"

    def test_mutates_in_place_and_returns_the_same_list(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with (
            mock.patch("backend.app.services.enrichment.lookup_vendor", return_value=None),
            mock.patch("backend.app.services.enrichment._lookup_hostname_async", return_value=None),
        ):
            result = enrich_devices(devices)

        assert result is devices
