from __future__ import annotations

import typing
"""Tests for main.scan_network().

scapy.srp() actually sending packets requires raw-socket access (root),
so these tests mock it out entirely and check only the parsing of its
return value - the part of scan_network() that's ordinary Python logic.
"""


from unittest import mock

import scapy.all as scapy
import main


def fake_answered_packet(ip, mac):
    """A stand-in for one (sent, received) tuple in srp()'s answered
    list. Only the [1] (received) side and its .psrc/.hwsrc are read by
    scan_network(), so that's all this needs to provide."""
    received = mock.Mock()
    received.psrc = ip
    received.hwsrc = mac
    return (mock.Mock(), received)


class TestScanNetwork:
    def test_returns_a_device_dict_per_answered_packet(self):
        answered = [
            fake_answered_packet("192.168.1.1", "9c:5a:6b:1e:4f:0c"),
            fake_answered_packet("192.168.1.2", "4a:7c:9f:3b:2d:8e"),
        ]
        with mock.patch("scapy.all.srp", return_value=(answered, [])):
            devices = main.scan_network("192.168.1.0/24")

        assert devices == [
            {"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"},
            {"ip": "192.168.1.2", "mac": "4a:7c:9f:3b:2d:8e"},
        ]

    def test_no_answered_packets_returns_empty_list(self):
        with mock.patch("scapy.all.srp", return_value=([], [])):
            devices = main.scan_network("192.168.1.0/24")

        assert devices == []

    def test_passes_the_network_through_to_the_arp_request(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            main.scan_network("192.168.1.0/24")

        sent_packet = mock_srp.call_args[0][0]
        assert sent_packet[getattr(scapy, 'ARP')].pdst == "192.168.1.0/24"

    def test_default_timeout_is_used_when_not_given(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            main.scan_network("192.168.1.0/24")

        assert mock_srp.call_args.kwargs["timeout"] == main.DEFAULT_TIMEOUT

    def test_custom_timeout_is_passed_through(self):
        """Regression test: the timeout used to be hardcoded to 1
        second regardless of the network's size - a /16 got the same
        window as a /24 and would systematically under-report."""
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            main.scan_network("192.168.1.0/24", timeout=5.0)

        assert mock_srp.call_args.kwargs["timeout"] == 5.0
