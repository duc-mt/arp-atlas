from __future__ import annotations

import socket
import threading
from unittest import mock

import main


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
            open_ports = main.scan_device_ports(
                "127.0.0.1", ports=[port], timeout=0.3
            )
            assert open_ports == [port]
        finally:
            srv.close()

    def test_closed_port_is_not_reported(self):
        # Port 1 is reserved and essentially guaranteed closed/refused
        # on a normal system without root running something unusual.
        open_ports = main.scan_device_ports(
            "127.0.0.1", ports=[1], timeout=0.3
        )
        assert open_ports == []

    def test_a_connection_error_is_treated_as_closed_not_a_crash(self):
        with mock.patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__.return_value.connect_ex.side_effect = (
                OSError("network unreachable")
            )
            open_ports = main.scan_device_ports(
                "10.255.255.255", ports=[22], timeout=0.1
            )
        assert open_ports == []

    def test_only_probes_the_given_ports(self):
        srv, port = start_local_listener()
        try:
            open_ports = main.scan_device_ports(
                "127.0.0.1", ports=[1, port, 2], timeout=0.3
            )
            assert open_ports == [port]
        finally:
            srv.close()


class TestClassifyDevice:
    def test_port_9100_is_a_printer(self):
        assert main.classify_device(None, [9100]) == "printer"

    def test_networking_vendor_is_router_switch(self):
        assert main.classify_device("Cisco Systems, Inc", []) == "router/switch"

    def test_networking_vendor_match_is_case_insensitive(self):
        assert main.classify_device("CISCO SYSTEMS", []) == "router/switch"

    def test_port_3389_is_windows_host(self):
        assert main.classify_device(None, [3389]) == "windows host"

    def test_port_22_is_server(self):
        assert main.classify_device(None, [22]) == "server"

    def test_port_80_is_web_enabled_device(self):
        assert main.classify_device(None, [80]) == "web-enabled device"

    def test_port_443_is_web_enabled_device(self):
        assert main.classify_device(None, [443]) == "web-enabled device"

    def test_no_signal_is_unknown(self):
        assert main.classify_device(None, []) == "unknown"

    def test_printer_port_takes_priority_over_vendor(self):
        assert main.classify_device("Cisco Systems", [9100]) == "printer"

    def test_none_vendor_and_none_ports_do_not_crash(self):
        assert main.classify_device(None, None) == "unknown"


class TestScanDevicesPorts:
    def test_adds_open_ports_and_role_to_each_device(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch(
            "main.scan_device_ports", return_value=[22]
        ):
            result = main.scan_devices_ports(devices)

        assert result[0]["open_ports"] == [22]
        assert result[0]["role"] == "server"

    def test_uses_vendor_from_the_device_for_classification(self):
        devices = [{
            "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa",
            "vendor": "Cisco Systems",
        }]

        with mock.patch("main.scan_device_ports", return_value=[]):
            result = main.scan_devices_ports(devices)

        assert result[0]["role"] == "router/switch"

    def test_mutates_in_place_and_returns_the_same_list(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

        with mock.patch("main.scan_device_ports", return_value=[]):
            result = main.scan_devices_ports(devices)

        assert result is devices
