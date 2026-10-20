"""
==============================================================================
Module Name:   test_port_scanner_async.py
Description:   Tests for the asyncio TCP connect port scanner.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_port_scanner_async.py
Notes:         Requires Python 3.10+. Uses asyncio.run() directly rather
               than a pytest-asyncio plugin, so it adds no dev dependency.
==============================================================================
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import typing
from unittest import mock

import pytest

from backend.app.config import SNMP_PORT
from backend.app.scanner.port_scanner_async import (
    async_scan_device_ports,
    async_scan_devices_ports,
    scan_devices_ports_async,
)

_MOD = "backend.app.scanner.port_scanner_async"


def start_local_listener() -> tuple[socket.socket, int]:
    """A real TCP listener on an ephemeral port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def accept_loop() -> None:
        try:
            while True:
                conn, _ = srv.accept()
                conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv, port


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _devices(count: int) -> list[dict[str, typing.Any]]:
    return [{"ip": f"192.168.1.{i}", "mac": f"aa:aa:aa:aa:aa:{i:02x}"} for i in range(1, count + 1)]


class _FakeWriter:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class TestAsyncScanDevicePorts:
    def test_finds_a_genuinely_open_port(self) -> None:
        srv, port = start_local_listener()
        try:
            result = asyncio.run(async_scan_device_ports("127.0.0.1", [port], timeout=0.5))
        finally:
            srv.close()
        assert result == [port]

    def test_closed_port_is_not_reported(self) -> None:
        result = asyncio.run(async_scan_device_ports("127.0.0.1", [_closed_port()], timeout=0.5))
        assert result == []

    def test_results_keep_the_order_the_ports_were_given_in(self) -> None:
        srv_a, port_a = start_local_listener()
        srv_b, port_b = start_local_listener()
        closed = _closed_port()
        try:
            ports = [port_b, closed, port_a]
            result = asyncio.run(async_scan_device_ports("127.0.0.1", ports, timeout=0.5))
        finally:
            srv_a.close()
            srv_b.close()
        assert result == [port_b, port_a]

    def test_timeout_counts_as_closed(self) -> None:
        async def hang(ip: str, port: int) -> typing.NoReturn:
            await asyncio.sleep(5)
            raise AssertionError("should have timed out")

        with mock.patch("asyncio.open_connection", hang):
            result = asyncio.run(async_scan_device_ports("10.255.255.1", [22, 80], timeout=0.05))
        assert result == []

    def test_connection_error_counts_as_closed(self) -> None:
        async def refuse(ip: str, port: int) -> typing.NoReturn:
            raise ConnectionRefusedError

        with mock.patch("asyncio.open_connection", refuse):
            assert asyncio.run(async_scan_device_ports("10.0.0.1", [22])) == []

    def test_a_reset_while_closing_is_not_an_error(self) -> None:
        class _ResetWriter(_FakeWriter):
            async def wait_closed(self) -> None:
                raise ConnectionResetError

        async def connect(ip: str, port: int) -> tuple[None, _ResetWriter]:
            return None, _ResetWriter()

        with mock.patch("asyncio.open_connection", connect):
            assert asyncio.run(async_scan_device_ports("10.0.0.1", [22])) == [22]

    def test_snmp_adds_161_when_an_agent_answers(self) -> None:
        with mock.patch(f"{_MOD}.snmp_probe", return_value=True) as mock_probe:
            result = asyncio.run(async_scan_device_ports("127.0.0.1", [], timeout=0.4, snmp=True))
        assert result == [SNMP_PORT]
        mock_probe.assert_called_once_with("127.0.0.1", 0.4)

    def test_snmp_is_off_by_default(self) -> None:
        with mock.patch(f"{_MOD}.snmp_probe") as mock_probe:
            asyncio.run(async_scan_device_ports("127.0.0.1", []))
        mock_probe.assert_not_called()


class TestSocketBudget:
    def test_never_more_connects_in_flight_than_the_cap(self) -> None:
        active = 0
        peak = 0

        async def slow_connect(ip: str, port: int) -> tuple[None, _FakeWriter]:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return None, _FakeWriter()

        with mock.patch("asyncio.open_connection", slow_connect):
            asyncio.run(
                async_scan_devices_ports(_devices(4), ports=list(range(1, 11)), fd_cap=3),
            )

        assert 1 < peak <= 3

    def test_the_cap_is_shared_across_devices_not_per_device(self) -> None:
        active = 0
        peak = 0

        async def slow_connect(ip: str, port: int) -> tuple[None, _FakeWriter]:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return None, _FakeWriter()

        # 8 devices x 2 ports would be 16 at once with a per-device cap of 2.
        with mock.patch("asyncio.open_connection", slow_connect):
            asyncio.run(async_scan_devices_ports(_devices(8), ports=[22, 80], fd_cap=2))

        assert peak <= 2

    def test_host_concurrency_bounds_devices_in_flight(self) -> None:
        active = 0
        peak = 0

        async def slow_scan(ip: str, *args: typing.Any, **kwargs: typing.Any) -> list[int]:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return []

        with mock.patch(f"{_MOD}.async_scan_device_ports", slow_scan):
            asyncio.run(async_scan_devices_ports(_devices(10), host_concurrency=2))

        assert 1 < peak <= 2

    def test_back_to_back_runs_with_contention_do_not_break(self) -> None:
        """Regression: a semaphore cached at module level is bound to the
        first event loop that contends on it, so the second asyncio.run()
        raised 'is bound to a different event loop'."""

        async def refuse(ip: str, port: int) -> typing.NoReturn:
            await asyncio.sleep(0.001)
            raise ConnectionRefusedError

        with mock.patch("asyncio.open_connection", refuse):
            for _ in range(3):
                devices = _devices(2)
                scan_devices_ports_async(devices, ports=list(range(1, 30)), fd_cap=2)
                assert all(d["open_ports"] == [] for d in devices)


class TestAsyncScanDevicesPorts:
    def test_adds_open_ports_and_role_in_place(self) -> None:
        devices = _devices(2)
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock.AsyncMock(return_value=[9100])):
            result = asyncio.run(async_scan_devices_ports(devices))

        assert result is devices
        assert devices[0]["open_ports"] == [9100]
        assert devices[0]["role"] == "printer"

    def test_vendor_feeds_the_classifier(self) -> None:
        devices = _devices(1)
        devices[0]["vendor"] = "Cisco Systems"
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock.AsyncMock(return_value=[23])):
            asyncio.run(async_scan_devices_ports(devices))
        assert devices[0]["role"] == "router/switch"

    def test_finds_a_real_open_port_end_to_end(self) -> None:
        srv, port = start_local_listener()
        devices = [{"ip": "127.0.0.1", "mac": "aa:aa:aa:aa:aa:aa"}]
        try:
            asyncio.run(
                async_scan_devices_ports(devices, ports=[port, _closed_port()], timeout=0.5)
            )
        finally:
            srv.close()
        assert devices[0]["open_ports"] == [port]

    def test_empty_device_list(self) -> None:
        assert asyncio.run(async_scan_devices_ports([])) == []

    def test_uses_the_port_timeout_not_the_arp_timeout(self) -> None:
        mock_scan = mock.AsyncMock(return_value=[])
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock_scan):
            asyncio.run(async_scan_devices_ports(_devices(1)))
        assert mock_scan.call_args.args[2] == 0.3

        mock_scan.reset_mock()
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock_scan):
            asyncio.run(async_scan_devices_ports(_devices(1), timeout=0.05))
        assert mock_scan.call_args.args[2] == 0.05

    def test_snmp_flag_is_passed_through(self) -> None:
        mock_scan = mock.AsyncMock(return_value=[])
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock_scan):
            asyncio.run(async_scan_devices_ports(_devices(1), snmp=True))
        assert mock_scan.call_args.kwargs["snmp"] is True

    def test_progress_callback_sees_every_device(self) -> None:
        seen: list[tuple[int, int, str]] = []
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock.AsyncMock(return_value=[])):
            asyncio.run(
                async_scan_devices_ports(
                    _devices(3),
                    progress_callback=lambda done, total, dev: seen.append(
                        (done, total, dev["ip"])
                    ),
                )
            )
        assert [(done, total) for done, total, _ in seen] == [(1, 3), (2, 3), (3, 3)]
        assert {ip for _, _, ip in seen} == {"192.168.1.1", "192.168.1.2", "192.168.1.3"}

    def test_a_failing_progress_callback_does_not_abort_the_scan(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        def boom(done: int, total: int, device: dict[str, typing.Any]) -> None:
            raise RuntimeError("bad callback")

        devices = _devices(3)
        with (
            caplog.at_level(logging.WARNING, logger=_MOD),
            mock.patch(f"{_MOD}.async_scan_device_ports", new=mock.AsyncMock(return_value=[])),
        ):
            asyncio.run(async_scan_devices_ports(devices, progress_callback=boom))

        assert all("open_ports" in d for d in devices)
        assert "progress_callback raised" in caplog.text


class TestBlockingWrapper:
    def test_scans_from_synchronous_code(self) -> None:
        devices = _devices(1)
        with mock.patch(f"{_MOD}.async_scan_device_ports", new=mock.AsyncMock(return_value=[22])):
            result = scan_devices_ports_async(devices)
        assert result is devices
        assert devices[0]["open_ports"] == [22]

    def test_refuses_to_run_inside_a_running_loop(self) -> None:
        async def caller() -> None:
            with pytest.raises(RuntimeError, match="running event loop"):
                scan_devices_ports_async(_devices(1))

        asyncio.run(caller())
