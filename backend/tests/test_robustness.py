"""
==============================================================================
Module Name:   test_robustness.py
Description:   Regression tests for failure isolation: one bad device, one
               failed lookup or one odd history file must never take the whole
               scan (or the whole CLI run) down with it.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-21
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_robustness.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

import pytest

from backend.app.scanner.classifier import scan_devices_ports
from backend.app.scanner.port_scanner_async import async_scan_devices_ports
from backend.app.services.enrichment import enrich_devices
from backend.app.services.history_service import load_history, save_scan
from backend.app.services.network_utils import is_permission_error

_CLS = "backend.app.scanner.classifier"
_ASYNC = "backend.app.scanner.port_scanner_async"


def _devices(count: int = 4) -> list[dict[str, Any]]:
    return [{"ip": f"192.168.1.{i}", "mac": f"aa:aa:aa:aa:aa:{i:02x}"} for i in range(1, count + 1)]


class TestOneBadDeviceDoesNotAbortThePortScan:
    """scan_devices_ports() used to re-raise the first per-device exception,
    discarding the results of every other device."""

    @staticmethod
    def _flaky(bad_ip: str, error: Exception) -> Any:
        def scan(ip: str, ports: Any, timeout: float, method: str = "connect", snmp: bool = False):
            if ip == bad_ip:
                raise error
            return [22]

        return scan

    def test_the_other_devices_are_still_scanned(self) -> None:
        devices = _devices()
        flaky = self._flaky("192.168.1.2", OSError("Network is unreachable"))
        with mock.patch(f"{_CLS}.scan_device_ports", flaky):
            result = scan_devices_ports(devices)

        assert result is devices
        assert [d.get("open_ports") for d in devices] == [[22], None, [22], [22]]

    def test_the_failed_device_is_left_unscanned_not_marked_clean(self) -> None:
        """No open_ports/role at all - 'scan failed' must not look like
        'scanned, nothing open'."""
        devices = _devices(2)
        flaky = self._flaky("192.168.1.1", RuntimeError("boom"))
        with mock.patch(f"{_CLS}.scan_device_ports", flaky):
            scan_devices_ports(devices)

        assert "open_ports" not in devices[0]
        assert "role" not in devices[0]
        assert devices[1]["open_ports"] == [22]

    def test_the_failure_is_reported(self, caplog: pytest.LogCaptureFixture) -> None:
        flaky = self._flaky("192.168.1.2", OSError("Network is unreachable"))
        with (
            caplog.at_level(logging.WARNING, logger=_CLS),
            mock.patch(f"{_CLS}.scan_device_ports", flaky),
        ):
            scan_devices_ports(_devices())

        assert "port scan of 192.168.1.2 failed" in caplog.text
        assert "Network is unreachable" in caplog.text

    def test_progress_still_reaches_the_total(self) -> None:
        seen: list[tuple[int, int]] = []
        flaky = self._flaky("192.168.1.2", OSError("nope"))
        with mock.patch(f"{_CLS}.scan_device_ports", flaky):
            scan_devices_ports(
                _devices(), progress_callback=lambda done, total, device: seen.append((done, total))
            )

        assert sorted(seen) == [(1, 4), (2, 4), (3, 4), (4, 4)]

    def test_a_permission_error_still_propagates(self) -> None:
        """If raw sockets are denied every device fails the same way: say so,
        rather than finishing 'successfully' with nothing scanned."""
        flaky = self._flaky("192.168.1.2", PermissionError("Operation not permitted"))
        with (
            mock.patch(f"{_CLS}.scan_device_ports", flaky),
            pytest.raises(PermissionError),
        ):
            scan_devices_ports(_devices())

    def test_scapys_wrapped_permission_error_also_propagates(self) -> None:
        class Scapy_Exception(Exception):
            pass

        flaky = self._flaky("192.168.1.2", Scapy_Exception("Permission denied: raw socket"))
        with (
            mock.patch(f"{_CLS}.scan_device_ports", flaky),
            pytest.raises(Scapy_Exception),
        ):
            scan_devices_ports(_devices())


class TestOneBadDeviceDoesNotAbortTheAsyncPortScan:
    def test_the_other_devices_are_still_scanned(self, caplog: pytest.LogCaptureFixture) -> None:
        async def fake_scan(ip: str, *args: Any, **kwargs: Any) -> list[int]:
            if ip == "192.168.1.2":
                raise RuntimeError("boom")
            return [22]

        devices = _devices()
        with (
            caplog.at_level(logging.WARNING, logger=_ASYNC),
            mock.patch(f"{_ASYNC}.async_scan_device_ports", fake_scan),
        ):
            asyncio.run(async_scan_devices_ports(devices))

        assert [d.get("open_ports") for d in devices] == [[22], None, [22], [22]]
        assert "role" not in devices[1]
        assert "port scan of 192.168.1.2 failed" in caplog.text

    def test_progress_still_reaches_the_total(self) -> None:
        async def fake_scan(ip: str, *args: Any, **kwargs: Any) -> list[int]:
            if ip == "192.168.1.1":
                raise RuntimeError("boom")
            return []

        seen: list[int] = []
        with mock.patch(f"{_ASYNC}.async_scan_device_ports", fake_scan):
            asyncio.run(
                async_scan_devices_ports(
                    _devices(3), progress_callback=lambda done, total, device: seen.append(done)
                )
            )
        assert seen == [1, 2, 3]


class TestOneFailedLookupDoesNotAbortEnrichment:
    def test_the_other_hostnames_are_still_resolved(self, caplog: pytest.LogCaptureFixture) -> None:
        async def lookup(ip: str, timeout: float) -> str | None:
            if ip == "192.168.1.2":
                raise OSError("Too many open files")
            return f"host-{ip.rsplit('.', 1)[1]}.local"

        devices = _devices(3)
        with (
            caplog.at_level(logging.WARNING),
            mock.patch("backend.app.services.enrichment._lookup_hostname_async", lookup),
            mock.patch("backend.app.services.enrichment.lookup_vendor", return_value=None),
        ):
            enrich_devices(devices)

        assert [d["hostname"] for d in devices] == ["host-1.local", None, "host-3.local"]
        assert all("vendor" in d for d in devices)
        assert "hostname lookup for 192.168.1.2 failed" in caplog.text


class TestIsPermissionError:
    def test_permission_error(self) -> None:
        assert is_permission_error(PermissionError("Operation not permitted"))

    def test_scapy_exception_wrapping_a_permission_failure(self) -> None:
        class Scapy_Exception(Exception):
            pass

        assert is_permission_error(Scapy_Exception("Permission denied"))

    @pytest.mark.parametrize("exc", [OSError("Network is unreachable"), ValueError("Permission")])
    def test_other_errors_are_not(self, exc: Exception) -> None:
        assert not is_permission_error(exc)

    def test_a_scapy_exception_for_another_reason_is_not(self) -> None:
        class Scapy_Exception(Exception):
            pass

        assert not is_permission_error(Scapy_Exception("no such device"))


class TestHistoryFileOfTheWrongShape:
    """load_history() treated an unparseable file as empty but trusted any file
    that happened to be valid JSON: a list, null, a string entry or non-dict
    devices crashed the CLI with an AttributeError the next time it ran."""

    _GOOD: ClassVar[dict[str, str]] = {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}

    @pytest.mark.parametrize(
        "content",
        [b"", b"{not json", b"\xff\xfe\x00\x80", b"[]", b"null", b'"text"', b"42", b"true"],
        ids=["empty", "garbage", "not-utf8", "list", "null", "string", "number", "bool"],
    )
    def test_unusable_files_load_as_empty_and_can_be_saved_over(
        self, tmp_path: Path, content: bytes
    ) -> None:
        path = tmp_path / "history.json"
        path.write_bytes(content)

        assert load_history(str(path)) == {}
        save_scan(str(path), "10.0.0.0/24", [self._GOOD])  # and the CLI can recover
        assert load_history(str(path))["10.0.0.0/24"]["devices"] == [self._GOOD]

    def test_malformed_entries_are_dropped_but_good_ones_kept(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "history.json"
        good = {"timestamp": "t", "devices": [self._GOOD]}
        path.write_text(
            json.dumps(
                {
                    "good": good,
                    "string-entry": "oops",
                    "no-devices": {"timestamp": "t"},
                    "devices-not-a-list": {"devices": "x"},
                    "device-not-a-dict": {"devices": ["x"]},
                    "null-entry": None,
                }
            )
        )

        with caplog.at_level(logging.WARNING, logger="backend.app.services.history_service"):
            history = load_history(str(path))

        assert history == {"good": good}
        assert "ignoring malformed history entry for 'string-entry'" in caplog.text

    def test_a_well_formed_history_is_returned_unchanged(self, tmp_path: Path) -> None:
        path = tmp_path / "history.json"
        data = {"10.0.0.0/24": {"timestamp": "t", "devices": [self._GOOD], "stats": {"x": 1}}}
        path.write_text(json.dumps(data))

        assert load_history(str(path)) == data

    def test_a_missing_file_is_still_empty(self, tmp_path: Path) -> None:
        assert load_history(str(tmp_path / "nope.json")) == {}
