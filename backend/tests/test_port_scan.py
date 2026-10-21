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

import pytest

from backend.app.scanner.classifier import (
    classify_device,
    classify_device_scored,
    scan_device_ports,
    scan_devices_ports,
)


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
    Mocks scapy.all.sr/send the same way test_scan_network.py mocks
    scapy.all.srp. The real-socket version is in test_raw_socket_integration.py
    (it needs raw-socket privileges, so it is skipped where they're missing)."""

    @staticmethod
    def _answer(port: int, flags: int, ack: int = 1, has_tcp: bool = True) -> tuple:
        """One (sent, received) pair as sr() returns it."""
        sent = mock.MagicMock()
        sent.__getitem__.return_value.dport = port  # sent[TCP].dport
        tcp_layer = mock.Mock()
        tcp_layer.flags = flags
        tcp_layer.ack = ack
        received = mock.Mock()
        received.haslayer.return_value = has_tcp
        received.getlayer.return_value = tcp_layer
        return sent, received

    def _scan(self, ports, answers, **kwargs):
        with (
            mock.patch("scapy.all.sr", return_value=(answers, [])) as mock_sr,
            mock.patch("scapy.all.send") as mock_send,
        ):
            result = scan_device_ports(
                "192.168.1.1", ports=ports, timeout=0.5, method="syn", **kwargs
            )
        return result, mock_sr, mock_send

    def test_syn_ack_is_reported_open_and_torn_down_with_a_rst(self):
        open_ports, _, mock_send = self._scan([80], [self._answer(80, 0x12)])

        assert open_ports == [80]
        mock_send.assert_called_once()  # RST sent - handshake never completed
        assert len(mock_send.call_args.args[0]) == 1

    def test_no_response_is_not_open(self):
        open_ports, _, mock_send = self._scan([81], [])
        assert open_ports == []
        mock_send.assert_not_called()

    def test_rst_ack_closed_port_is_not_open(self):
        open_ports, _, mock_send = self._scan([81], [self._answer(81, 0x14)])
        assert open_ports == []
        mock_send.assert_not_called()

    def test_non_tcp_reply_is_ignored(self):
        open_ports, _, mock_send = self._scan([80], [self._answer(80, 0x12, has_tcp=False)])
        assert open_ports == []
        mock_send.assert_not_called()

    def test_only_open_ports_are_returned_in_the_order_given(self):
        answers = [
            self._answer(82, 0x12),  # replies arrive in any order
            self._answer(81, 0x14),
            self._answer(80, 0x12),
        ]
        open_ports, _, mock_send = self._scan([80, 81, 82, 83], answers)

        assert open_ports == [80, 82]
        assert len(mock_send.call_args.args[0]) == 2  # one RST per open port

    def test_all_ports_go_out_in_a_single_sr_call(self):
        """The point of batching: one timeout window per host, not per port."""
        _, mock_sr, _ = self._scan([22, 80, 443], [])

        mock_sr.assert_called_once()
        syns = mock_sr.call_args.args[0]
        assert syns["TCP"].dport == [22, 80, 443]
        assert syns["TCP"].flags == "S"
        assert mock_sr.call_args.kwargs["timeout"] == 0.5

    def test_batch_uses_one_ephemeral_source_port_shared_with_the_rsts(self):
        answers = [self._answer(80, 0x12, ack=777)]
        _, mock_sr, mock_send = self._scan([80, 81], answers)

        sport = mock_sr.call_args.args[0]["TCP"].sport
        assert 40000 <= sport < 60000
        rst = mock_send.call_args.args[0][0]["TCP"]
        assert (rst.sport, rst.dport, rst.flags, rst.seq) == (sport, 80, "R", 777)

    def test_empty_port_list_sends_nothing(self):
        open_ports, mock_sr, mock_send = self._scan([], [])
        assert open_ports == []
        mock_sr.assert_not_called()
        mock_send.assert_not_called()

    def test_default_method_never_touches_scapy(self):
        with mock.patch("scapy.all.sr") as mock_sr, mock.patch("scapy.all.sr1") as mock_sr1:
            scan_device_ports("127.0.0.1", ports=[1], timeout=0.1)
        mock_sr.assert_not_called()
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


class TestClassifyDeviceHostname:
    """A device's own name is often a stronger clue than one open port."""

    @pytest.mark.parametrize(
        ("hostname", "role"),
        [
            ("ESP_1A2B3C", "smart home device"),
            ("shelly1-ABC123", "smart home device"),
            ("DESKTOP-AB12CD3", "windows host"),
            ("LAPTOP-9XY12Z", "windows host"),
            ("WIN-0A1B2C3D", "windows host"),
            ("BRN30055C1234", "printer"),
            ("NPI1A2B3C", "printer"),
            ("laserjet-2nd-floor", "printer"),
            ("ipcam-front-door", "ip camera"),
            ("hikvision-01", "ip camera"),
            ("AP-Lobby", "access point"),
            ("uap-ac-pro", "access point"),
            ("SW-ACCESS-01", "router/switch"),
            ("FW-CORE.example.com", "router/switch"),
            ("R1", "router/switch"),
            ("raspberrypi", "linux host"),
            ("synology-nas", "server"),
        ],
    )
    def test_hostname_alone_can_name_the_role(self, hostname: str, role: str) -> None:
        assert classify_device(None, [], hostname) == role

    @pytest.mark.parametrize("hostname", [None, "", "johns-macbook", "iphone-of-bob", "R10X"])
    def test_a_name_that_says_nothing_changes_nothing(self, hostname: str | None) -> None:
        assert classify_device(None, [], hostname) == "unknown"

    def test_only_the_host_part_of_a_fqdn_counts(self) -> None:
        # "printer" in the *domain* says nothing about the device itself.
        assert classify_device(None, [], "johns-macbook.printer.example.com") == "unknown"

    def test_a_hint_never_outweighs_a_strong_port_signature(self) -> None:
        # Port 9100 is a strong printer signal (5 points); a camera-ish
        # name is only worth 3.
        assert classify_device(None, [9100], "ipcam-1") == "printer"

    def test_a_hint_settles_a_weak_tie(self) -> None:
        # SSH alone ties "server" with "linux host", i.e. unknown ...
        assert classify_device(None, [22]) == "unknown"
        # ... and the name breaks the tie.
        assert classify_device(None, [22], "raspberrypi") == "linux host"

    def test_hostname_is_optional_and_changes_nothing_when_omitted(self) -> None:
        for vendor, ports in [(None, [554]), ("Cisco Systems", [23]), (None, [22]), (None, [])]:
            assert classify_device(vendor, ports) == classify_device(vendor, ports, None)


class TestClassifyDeviceScored:
    def test_strong_port_signature_scores_five(self) -> None:
        assert classify_device_scored(None, [554]) == ("ip camera", 5)

    def test_a_hostname_hint_scores_three(self) -> None:
        assert classify_device_scored(None, [], "ESP_1A2B3C") == ("smart home device", 3)

    def test_hint_and_ports_add_up(self) -> None:
        assert classify_device_scored(None, [554], "ipcam-1") == ("ip camera", 8)

    def test_no_evidence_is_unknown_with_score_zero(self) -> None:
        assert classify_device_scored(None, []) == ("unknown", 0)

    def test_a_tie_is_unknown_with_score_zero(self) -> None:
        assert classify_device_scored(None, [22]) == ("unknown", 0)

    def test_classify_device_is_the_role_half_of_it(self) -> None:
        for ports in ([554], [22], [], [9100, 80]):
            assert classify_device(None, ports) == classify_device_scored(None, ports)[0]


class TestScanDevicesPortsUsesHostname:
    def test_enriched_hostname_feeds_the_classifier(self) -> None:
        devices: list[dict[str, typing.Any]] = [
            {"ip": "192.168.1.10", "mac": "aa", "hostname": "ESP_1A2B3C"},
            {"ip": "192.168.1.11", "mac": "bb", "hostname": None},
            {"ip": "192.168.1.12", "mac": "cc"},  # not enriched at all
        ]
        with mock.patch("backend.app.scanner.classifier.scan_device_ports", return_value=[]):
            scan_devices_ports(devices)

        assert [d["role"] for d in devices] == ["smart home device", "unknown", "unknown"]
