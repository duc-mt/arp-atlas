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

import asyncio
import typing
from unittest import mock

from backend.app.services.enrichment import _run_blocking, enrich_devices


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


class TestEnrichDevicesMultiProtocolHostnames:
    """Covers the hostname-resolution upgrade: reverse DNS, mDNS, LLMNR
    and NBNS now all race for each device, so these mock at the
    individual-protocol level (rather than mocking
    `_lookup_hostname_async` wholesale, as the tests above do) to prove
    the mDNS and NBNS legs are actually wired in and that whichever one
    answers becomes the device's hostname.
    """

    def test_mdns_result_is_used_when_reverse_dns_has_nothing(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.30", "mac": "aa:aa:aa:aa:aa:aa"}]

        with (
            mock.patch("backend.app.services.enrichment.lookup_vendor", return_value=None),
            mock.patch("backend.app.services.enrichment._reverse_dns_lookup", return_value=None),
            mock.patch(
                "backend.app.services.enrichment._mdns_lookup",
                return_value="nas-01.local",
            ),
            mock.patch("backend.app.services.enrichment._llmnr_lookup", return_value=None),
            mock.patch("backend.app.services.enrichment._nbns_lookup", return_value=None),
        ):
            result = enrich_devices(devices)

        assert result[0]["hostname"] == "nas-01.local"

    def test_netbios_result_is_used_when_nothing_else_answers(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.31", "mac": "bb:bb:bb:bb:bb:bb"}]

        with (
            mock.patch("backend.app.services.enrichment.lookup_vendor", return_value=None),
            mock.patch("backend.app.services.enrichment._reverse_dns_lookup", return_value=None),
            mock.patch("backend.app.services.enrichment._mdns_lookup", return_value=None),
            mock.patch("backend.app.services.enrichment._llmnr_lookup", return_value=None),
            mock.patch(
                "backend.app.services.enrichment._nbns_lookup",
                return_value="DESKTOP-ABC123",
            ),
        ):
            result = enrich_devices(devices)

        assert result[0]["hostname"] == "DESKTOP-ABC123"

    def test_each_device_gets_the_right_protocol_result_independently(self):
        devices: list[dict[str, typing.Any]] = [
            {"ip": "192.168.1.1", "mac": "10:5f:02:00:00:01"},  # resolves via mDNS
            {"ip": "192.168.1.2", "mac": "aa:aa:aa:aa:aa:aa"},  # resolves via NBNS
            {"ip": "192.168.1.3", "mac": "bb:bb:bb:bb:bb:bb"},  # resolves via nothing
        ]

        with (
            mock.patch(
                "backend.app.services.enrichment._reverse_dns_lookup",
                side_effect=[None, None, None],
            ),
            mock.patch(
                "backend.app.services.enrichment._mdns_lookup",
                side_effect=["router.local", None, None],
            ),
            mock.patch(
                "backend.app.services.enrichment._llmnr_lookup",
                side_effect=[None, None, None],
            ),
            mock.patch(
                "backend.app.services.enrichment._nbns_lookup",
                side_effect=[None, "WIN-FILESERVER", None],
            ),
        ):
            result = enrich_devices(devices)

        assert result[0]["vendor"] == "Ruijie Networks Co.,LTD"  # custom OUI db, same upgrade
        assert result[0]["hostname"] == "router.local"
        assert result[1]["hostname"] == "WIN-FILESERVER"
        assert result[2]["hostname"] is None


class TestEnrichDevicesInsideARunningLoop:
    """enrich_devices() used to call asyncio.run() unconditionally, which
    raises RuntimeError when the calling thread already has a running
    loop (a Jupyter cell, an async web handler, a pipeline that also uses
    the async port scanner)."""

    def test_works_when_called_from_a_coroutine(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        async def caller():
            return enrich_devices(devices)

        with (
            mock.patch("backend.app.services.enrichment.lookup_vendor", return_value="Vendor A"),
            mock.patch(
                "backend.app.services.enrichment._lookup_hostname_async",
                return_value="host-a.local",
            ),
        ):
            result = asyncio.run(caller())

        assert result is devices
        assert devices[0]["vendor"] == "Vendor A"
        assert devices[0]["hostname"] == "host-a.local"

    def test_run_blocking_returns_the_value_without_a_running_loop(self):
        async def answer():
            return 42

        assert _run_blocking(answer()) == 42

    def test_run_blocking_returns_the_value_inside_a_running_loop(self):
        async def answer():
            return 42

        async def caller():
            return _run_blocking(answer())

        assert asyncio.run(caller()) == 42

    def test_run_blocking_propagates_exceptions_from_the_coroutine(self):
        async def fail():
            raise ValueError("boom")

        async def caller():
            return _run_blocking(fail())

        for runner in (lambda: _run_blocking(fail()), lambda: asyncio.run(caller())):
            try:
                runner()
            except ValueError as e:
                assert str(e) == "boom"
            else:
                raise AssertionError("expected ValueError")
