"""
==============================================================================
Module Name:   test_scan_network.py
Description:   Source module test_scan_network.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_scan_network.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import scapy.all as scapy

from backend.app.config import DEFAULT_TIMEOUT
from backend.app.scanner.arp_scanner import scan_network


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
            devices = scan_network("192.168.1.0/24")

        assert devices == [
            {"ip": "192.168.1.1", "mac": "9c:5a:6b:1e:4f:0c"},
            {"ip": "192.168.1.2", "mac": "4a:7c:9f:3b:2d:8e"},
        ]

    def test_no_answered_packets_returns_empty_list(self):
        with mock.patch("scapy.all.srp", return_value=([], [])):
            devices = scan_network("192.168.1.0/24")

        assert devices == []

    def test_passes_the_network_through_to_the_arp_request(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/24")

        sent_packet = mock_srp.call_args[0][0]
        assert sent_packet[scapy.ARP].pdst == "192.168.1.0/24"  # type: ignore[attr-defined]

    def test_default_timeout_is_used_when_not_given(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/24")

        assert mock_srp.call_args.kwargs["timeout"] == DEFAULT_TIMEOUT

    def test_custom_timeout_is_passed_through(self):
        """Regression test: the timeout used to be hardcoded to 1
        second regardless of the network's size - a /16 got the same
        window as a /24 and would systematically under-report."""
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/24", timeout=5.0)

        assert mock_srp.call_args.kwargs["timeout"] == 5.0

    def test_default_mode_sends_one_broadcast_for_the_whole_range(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/24")  # gentle=False by default

        mock_srp.assert_called_once()


def _probed_ips(mock_srp: mock.Mock) -> list[str]:
    """The pdst of each ARP request scan_network() handed to srp(),
    in call order."""
    arp_layer: Any = scapy.ARP  # type: ignore[attr-defined]
    return [call.args[0][arp_layer].pdst for call in mock_srp.call_args_list]


class TestScanNetworkGentleMode:
    """gentle=True: one host at a time, shuffled order, jittered delay -
    see scan_network()'s docstring for why."""

    def test_probes_each_host_individually_not_the_whole_range_at_once(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/30", gentle=True)  # /30 => 2 usable hosts

        assert mock_srp.call_count == 2
        assert set(_probed_ips(mock_srp)) == {"192.168.1.1", "192.168.1.2"}

    def test_collects_replies_across_the_separate_per_host_calls(self):
        answered_1 = [fake_answered_packet("192.168.1.1", "aa:aa:aa:aa:aa:aa")]
        answered_2 = [fake_answered_packet("192.168.1.2", "bb:bb:bb:bb:bb:bb")]
        with mock.patch("scapy.all.srp", side_effect=[(answered_1, []), (answered_2, [])]):
            devices = scan_network("192.168.1.0/30", gentle=True)

        assert devices == [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]

    def test_order_is_shuffled_not_sequential(self):
        # Replace the shuffle with a deterministic reversal so the test
        # isn't flaky, while still proving the natural .1/.2/.3/... order
        # was changed before probing started.
        with (
            mock.patch("random.shuffle", side_effect=lambda lst: lst.reverse()),
            mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp,
        ):
            scan_network("192.168.1.0/29", gentle=True)  # /29 => 6 usable hosts

        probed_in_order = _probed_ips(mock_srp)
        assert probed_in_order[0] == "192.168.1.6"  # reversed order => last host probed first

    def test_sleeps_between_hosts_with_a_jittered_not_fixed_delay(self):
        with (
            mock.patch("scapy.all.srp", return_value=([], [])),
            mock.patch("time.sleep") as mock_sleep,
            mock.patch("random.uniform", return_value=0.02) as mock_uniform,
        ):
            scan_network("192.168.1.0/30", gentle=True, jitter_range=(0.01, 0.05))

        # /30 => 2 hosts => exactly one gap between them, drawn from the
        # given jitter range rather than a hardcoded constant.
        mock_sleep.assert_called_once_with(0.02)
        mock_uniform.assert_called_once_with(0.01, 0.05)

    def test_a_pre_expanded_host_list_is_used_as_is(self):
        targets = ["10.0.0.5", "10.0.0.9"]
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network(targets, gentle=True)

        assert set(_probed_ips(mock_srp)) == set(targets)
