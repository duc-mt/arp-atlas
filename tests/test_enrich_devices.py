from __future__ import annotations

from unittest import mock

import main


class TestEnrichDevices:
    def test_adds_vendor_and_hostname_to_each_device(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]

        with mock.patch(
            "main.lookup_vendor", side_effect=["Vendor A", None]
        ), mock.patch(
            "main._lookup_hostname_async", side_effect=[None, "host-b.local"]
        ):
            result = main.enrich_devices(devices)

        assert result[0]["vendor"] == "Vendor A"
        assert result[0]["hostname"] is None
        assert result[1]["vendor"] is None
        assert result[1]["hostname"] == "host-b.local"

    def test_mutates_in_place_and_returns_the_same_list(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch("main.lookup_vendor", return_value=None), \
             mock.patch("main._lookup_hostname_async", return_value=None):
            result = main.enrich_devices(devices)

        assert result is devices
