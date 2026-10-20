"""
==============================================================================
Module Name:   test_snmp_probe.py
Description:   Tests for classifier.snmp_probe() against a real local UDP
               socket, and for the snmp / max_workers options of
               scan_device_ports() and scan_devices_ports().
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_snmp_probe.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
import typing
from collections.abc import Callable
from unittest import mock

from backend.app.config import MAX_SCAN_WORKERS, SNMP_PORT
from backend.app.scanner.classifier import (
    _snmp_get_request,
    scan_device_ports,
    scan_devices_ports,
    snmp_probe,
)

# Byte layout of the request built by _snmp_get_request(): the request id
# sits right after the community string and the PDU header.
_ID_SLICE = slice(17, 21)


def _request_id(packet: bytes) -> bytes:
    return packet[_ID_SLICE]


def _reply_for(request: bytes) -> bytes:
    """A minimal but well-formed-looking SNMP response echoing the id."""
    body = b"\x02\x01\x01\x04\x06public\xa2\x0b\x02\x04" + _request_id(request) + b"\x02\x01\x00"
    return b"\x30" + bytes([len(body)]) + body


def start_fake_agent(
    reply_fn: Callable[[bytes], bytes | None],
) -> tuple[socket.socket, int]:
    """A one-shot UDP responder on 127.0.0.1. `reply_fn` gets the request
    and returns the datagram to send back (or None to stay silent)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)

    def serve() -> None:
        try:
            data, addr = srv.recvfrom(1500)
            reply = reply_fn(data)
            if reply is not None:
                srv.sendto(reply, addr)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


class TestSnmpRequestPacket:
    def test_is_a_wellformed_sequence(self) -> None:
        packet = _snmp_get_request(0x01020304, b"public")
        assert packet[0] == 0x30
        assert packet[1] == len(packet) - 2

    def test_is_a_v2c_get_request_with_the_community(self) -> None:
        packet = _snmp_get_request(0x01020304, b"public")
        assert packet[2:5] == b"\x02\x01\x01"  # version 1 = SNMPv2c
        assert packet[5:13] == b"\x04\x06public"
        assert packet[13] == 0xA0  # GetRequest-PDU

    def test_carries_the_request_id(self) -> None:
        assert _request_id(_snmp_get_request(0x01020304, b"public")) == b"\x01\x02\x03\x04"

    def test_asks_for_sysdescr(self) -> None:
        packet = _snmp_get_request(0x01020304, b"public")
        assert packet.endswith(bytes([0x06, 0x08, 0x2B, 0x06, 1, 2, 1, 1, 1, 0, 0x05, 0x00]))


class TestSnmpProbe:
    def test_agent_that_answers_is_detected(self) -> None:
        srv, port = start_fake_agent(_reply_for)
        try:
            assert snmp_probe("127.0.0.1", timeout=2.0, port=port) is True
        finally:
            srv.close()

    def test_agent_only_answers_the_right_community(self) -> None:
        def reply(request: bytes) -> bytes | None:
            return _reply_for(request) if b"secret" in request else None

        srv, port = start_fake_agent(reply)
        try:
            assert snmp_probe("127.0.0.1", timeout=2.0, port=port, community=b"secret") is True
        finally:
            srv.close()

        srv, port = start_fake_agent(reply)
        try:
            assert snmp_probe("127.0.0.1", timeout=0.3, port=port) is False
        finally:
            srv.close()

    def test_reply_with_the_wrong_request_id_is_rejected(self) -> None:
        def reply(request: bytes) -> bytes | None:
            return _reply_for(b"\x00" * 17 + b"\xff\xff\xff\xff")

        srv, port = start_fake_agent(reply)
        try:
            assert snmp_probe("127.0.0.1", timeout=2.0, port=port) is False
        finally:
            srv.close()

    def test_non_snmp_reply_is_rejected(self) -> None:
        srv, port = start_fake_agent(lambda request: b"hello")
        try:
            assert snmp_probe("127.0.0.1", timeout=2.0, port=port) is False
        finally:
            srv.close()

    def test_silence_is_a_timeout_not_a_crash(self) -> None:
        srv, port = start_fake_agent(lambda request: None)
        try:
            assert snmp_probe("127.0.0.1", timeout=0.2, port=port) is False
        finally:
            srv.close()

    def test_nothing_listening_is_not_a_crash(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        assert snmp_probe("127.0.0.1", timeout=0.3, port=port) is False

    def test_a_socket_error_is_treated_as_no_agent(self) -> None:
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__.return_value.send.side_effect = OSError(
                "network unreachable"
            )
            assert snmp_probe("10.255.255.255", timeout=0.1) is False


_CLS = "backend.app.scanner.classifier"


class TestScanDevicePortsSnmpOption:
    def test_off_by_default(self) -> None:
        with (
            mock.patch(f"{_CLS}._tcp_connect_scan", return_value=[22]),
            mock.patch(f"{_CLS}.snmp_probe") as mock_probe,
        ):
            assert scan_device_ports("192.168.1.1", ports=[22]) == [22]
        mock_probe.assert_not_called()

    def test_answering_agent_adds_161_after_the_tcp_ports(self) -> None:
        with (
            mock.patch(f"{_CLS}._tcp_connect_scan", return_value=[22, 80]),
            mock.patch(f"{_CLS}.snmp_probe", return_value=True) as mock_probe,
        ):
            result = scan_device_ports("192.168.1.1", ports=[22, 80], timeout=0.4, snmp=True)
        assert result == [22, 80, SNMP_PORT]
        mock_probe.assert_called_once_with("192.168.1.1", 0.4)

    def test_silent_agent_adds_nothing(self) -> None:
        with (
            mock.patch(f"{_CLS}._tcp_connect_scan", return_value=[22]),
            mock.patch(f"{_CLS}.snmp_probe", return_value=False),
        ):
            assert scan_device_ports("192.168.1.1", ports=[22], snmp=True) == [22]

    def test_161_is_not_duplicated(self) -> None:
        with (
            mock.patch(f"{_CLS}._tcp_connect_scan", return_value=[161]),
            mock.patch(f"{_CLS}.snmp_probe") as mock_probe,
        ):
            assert scan_device_ports("192.168.1.1", ports=[161], snmp=True) == [161]
        mock_probe.assert_not_called()

    def test_works_with_the_syn_method_too(self) -> None:
        with (
            mock.patch(f"{_CLS}._tcp_syn_scan", return_value=[443]),
            mock.patch(f"{_CLS}.snmp_probe", return_value=True),
        ):
            result = scan_device_ports("192.168.1.1", ports=[443], method="syn", snmp=True)
        assert result == [443, SNMP_PORT]


def _devices(count: int) -> list[dict[str, typing.Any]]:
    return [{"ip": f"192.168.1.{i}", "mac": f"aa:aa:aa:aa:aa:{i:02x}"} for i in range(1, count + 1)]


class TestScanDevicesPortsOptions:
    def test_snmp_defaults_to_off_and_is_passed_through(self) -> None:
        with mock.patch(f"{_CLS}.scan_device_ports", return_value=[]) as mock_scan:
            scan_devices_ports(_devices(1))
        assert mock_scan.call_args.kwargs["snmp"] is False

        with mock.patch(f"{_CLS}.scan_device_ports", return_value=[]) as mock_scan:
            scan_devices_ports(_devices(1), snmp=True)
        assert mock_scan.call_args.kwargs["snmp"] is True

    def test_161_from_snmp_feeds_the_classifier(self) -> None:
        devices = _devices(1)
        devices[0]["vendor"] = "Cisco Systems"
        with mock.patch(f"{_CLS}.scan_device_ports", return_value=[161]):
            scan_devices_ports(devices, snmp=True)
        assert devices[0]["role"] == "router/switch"

    def _worker_count(self, devices: list[dict[str, typing.Any]], **kwargs: typing.Any) -> int:
        with (
            mock.patch(f"{_CLS}.scan_device_ports", return_value=[]),
            mock.patch.object(
                concurrent.futures,
                "ThreadPoolExecutor",
                wraps=concurrent.futures.ThreadPoolExecutor,
            ) as mock_pool,
        ):
            scan_devices_ports(devices, **kwargs)
        return int(mock_pool.call_args.kwargs["max_workers"])

    def test_default_worker_cap(self) -> None:
        assert self._worker_count(_devices(MAX_SCAN_WORKERS + 20)) == MAX_SCAN_WORKERS

    def test_max_workers_is_configurable(self) -> None:
        assert self._worker_count(_devices(20), max_workers=4) == 4

    def test_never_more_workers_than_devices(self) -> None:
        assert self._worker_count(_devices(3), max_workers=10) == 3

    def test_empty_device_list_is_fine(self) -> None:
        devices: list[dict[str, typing.Any]] = []
        assert self._worker_count(devices) == 1
        assert scan_devices_ports(devices) == []
