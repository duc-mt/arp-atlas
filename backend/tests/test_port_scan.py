"""
==============================================================================
Module Name:   test_port_scan.py
Description:   Source module test_port_scan.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_port_scan.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import socket
import threading
import typing
from unittest import mock

from backend.app.scanner.classifier import classify_device, scan_device_ports, scan_devices_ports


def start_local_listener():
    """Start a real TCP listener on an ephemeral port, for testing
    scan_device_ports() against a genuine open port rather than
    mocking sockets."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept_loop():
        try:
            while True:
                conn, _ = srv.accept()
                conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return srv, port


class TestScanDevicePorts:
    def test_finds_a_genuinely_open_port(self):
        srv, port = start_local_listener()
        try:
            open_ports = scan_device_ports("127.0.0.1", ports=[port], timeout=0.3)
            assert open_ports == [port]
        finally:
            srv.close()

    def test_closed_port_is_not_reported(self):
        # Port 1 is reserved and essentially guaranteed closed/refused
        # on a normal system without root running something unusual.
        open_ports = scan_device_ports("127.0.0.1", ports=[1], timeout=0.3)
        assert open_ports == []

    def test_a_connection_error_is_treated_as_closed_not_a_crash(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__.return_value.connect_ex.side_effect = OSError(
                "network unreachable"
            )
            open_ports = scan_device_ports("10.255.255.255", ports=[22], timeout=0.1)
        assert open_ports == []

    def test_only_probes_the_given_ports(self):
        srv, port = start_local_listener()
        try:
            open_ports = scan_device_ports("127.0.0.1", ports=[1, port, 2], timeout=0.3)
            assert open_ports == [port]
        finally:
            srv.close()


class TestScanDevicePortsSynMethod:
    """method="syn" (half-open scan via scapy) - see _tcp_syn_scan.
    Mocks scapy.all.sr1/send the same way test_scan_network.py mocks
    scapy.all.srp, since this also needs raw-socket privileges and
    can't be exercised against a real listener in CI."""

    @staticmethod
    def _fake_response(flags: int, ack: int = 1) -> mock.Mock:
        tcp_layer = mock.Mock()
        tcp_layer.flags = flags
        tcp_layer.ack = ack
        response = mock.Mock()
        response.haslayer.return_value = True
        response.getlayer.return_value = tcp_layer
        return response

    def test_syn_ack_is_reported_open_and_torn_down_with_a_rst(self):
        with (
            mock.patch("scapy.all.sr1", return_value=self._fake_response(0x12)),
            mock.patch("scapy.all.send") as mock_send,
        ):
            open_ports = scan_device_ports("192.168.1.1", ports=[80], timeout=0.5, method="syn")

        assert open_ports == [80]
        mock_send.assert_called_once()  # RST sent - handshake never completed

    def test_no_response_is_not_open(self):
        with mock.patch("scapy.all.sr1", return_value=None):
            open_ports = scan_device_ports("192.168.1.1", ports=[81], timeout=0.5, method="syn")
        assert open_ports == []

    def test_rst_ack_closed_port_is_not_open(self):
        with mock.patch("scapy.all.sr1", return_value=self._fake_response(0x14)):
            open_ports = scan_device_ports("192.168.1.1", ports=[81], timeout=0.5, method="syn")
        assert open_ports == []

    def test_only_syn_ack_open_ports_get_an_rst(self):
        closed = self._fake_response(0x14)
        with (
            mock.patch("scapy.all.sr1", return_value=closed),
            mock.patch("scapy.all.send") as mock_send,
        ):
            scan_device_ports("192.168.1.1", ports=[81], timeout=0.5, method="syn")
        mock_send.assert_not_called()

    def test_default_method_never_touches_scapy(self):
        with mock.patch("scapy.all.sr1") as mock_sr1:
            scan_device_ports("127.0.0.1", ports=[1], timeout=0.1)
        mock_sr1.assert_not_called()


class TestClassifyDevice:
    def test_port_9100_is_a_printer(self):
        assert classify_device(None, [9100]) == "printer"

    def test_networking_vendor_is_router_switch(self):
        assert classify_device("Cisco Systems, Inc", []) == "router/switch"

    def test_networking_vendor_match_is_case_insensitive(self):
        assert classify_device("CISCO SYSTEMS", []) == "router/switch"

    def test_port_3389_is_windows_host(self):
        assert classify_device(None, [3389]) == "windows host"

    def test_port_22_is_unknown(self):
        assert classify_device(None, [22]) == "unknown"

    def test_port_80_is_web_enabled_device(self):
        assert classify_device(None, [80]) == "web-enabled device"

    def test_port_443_is_web_enabled_device(self):
        assert classify_device(None, [443]) == "web-enabled device"

    def test_no_signal_is_unknown(self):
        assert classify_device(None, []) == "unknown"

    def test_printer_port_takes_priority_over_vendor(self):
        assert classify_device("Cisco Systems", [9100]) == "printer"

    def test_none_vendor_and_none_ports_do_not_crash(self):
        assert classify_device(None, []) == "unknown"


class TestScanDevicesPorts:
    def test_adds_open_ports_and_role_to_each_device(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch("backend.app.scanner.classifier.scan_device_ports", return_value=[22, 21]):
            result = scan_devices_ports(devices)

        assert result[0]["open_ports"] == [22, 21]
        assert result[0]["role"] == "server"

    def test_uses_vendor_from_the_device_for_classification(self):
        devices: list[dict[str, typing.Any]] = [
            {
                "ip": "192.168.1.1",
                "mac": "aa:aa:aa:aa:aa:aa",
                "vendor": "Cisco Systems",
            }
        ]

        with mock.patch("backend.app.scanner.classifier.scan_device_ports", return_value=[]):
            result = scan_devices_ports(devices)

        assert result[0]["role"] == "router/switch"

    def test_mutates_in_place_and_returns_the_same_list(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch("backend.app.scanner.classifier.scan_device_ports", return_value=[]):
            result = scan_devices_ports(devices)

        assert result is devices

    def test_defaults_to_the_connect_method(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch(
            "backend.app.scanner.classifier.scan_device_ports", return_value=[]
        ) as mock_scan_ports:
            scan_devices_ports(devices)

        assert mock_scan_ports.call_args.kwargs["method"] == "connect"

    def test_method_is_passed_through_to_scan_device_ports(self):
        devices: list[dict[str, typing.Any]] = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch(
            "backend.app.scanner.classifier.scan_device_ports", return_value=[]
        ) as mock_scan_ports:
            scan_devices_ports(devices, method="syn")

        assert mock_scan_ports.call_args.kwargs["method"] == "syn"
