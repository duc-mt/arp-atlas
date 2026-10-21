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

from typing import ClassVar
from unittest import mock

import pytest
import scapy.all as scapy

from backend.app.config import DEFAULT_ARP_RETRIES, DEFAULT_TIMEOUT
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


class TestScanNetworkRetries:
    """The normal sweep re-sends unanswered requests; one shot loses
    replies on busy Wi-Fi and from sleeping devices."""

    def test_default_is_one_retry(self):
        with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
            scan_network("192.168.1.0/24")

        assert DEFAULT_ARP_RETRIES == 1
        assert mock_srp.call_args.kwargs["retry"] == DEFAULT_ARP_RETRIES

    def test_retries_are_passed_through(self):
        for retries in (0, 3):
            with mock.patch("scapy.all.srp", return_value=([], [])) as mock_srp:
                scan_network("192.168.1.0/24", retries=retries)
            assert mock_srp.call_args.kwargs["retry"] == retries

    def test_gentle_mode_ignores_retries(self):
        """Re-probing nearly every host would defeat the point of pacing."""
        sent = []
        with (
            mock.patch("scapy.all.AsyncSniffer", _FakeSniffer),
            mock.patch("scapy.all.sendp", lambda frame, **kw: sent.append(frame)),
            mock.patch("time.sleep"),
            mock.patch("scapy.all.srp") as mock_srp,
        ):
            scan_network("192.168.1.0/30", gentle=True, retries=5)

        mock_srp.assert_not_called()
        assert len(sent) == 2  # /30 => 2 hosts, each probed once


class _FakeSniffer:
    """Stand-in for scapy.AsyncSniffer that records what scan_network()
    asks of it. `events` (class attribute) is a shared log of start/stop."""

    events: ClassVar[list[str]] = []
    last: ClassVar[_FakeSniffer | None] = None
    starts_ok: ClassVar[bool] = True

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.prn = kwargs["prn"]
        self.running = False
        _FakeSniffer.last = self

    def start(self):
        _FakeSniffer.events.append("start")
        if _FakeSniffer.starts_ok:
            self.running = True
            self.kwargs["started_callback"]()

    def stop(self):
        _FakeSniffer.events.append("stop")
        self.running = False


def _arp_packet(op, ip, mac):
    return scapy.Ether() / scapy.ARP(op=op, psrc=ip, hwsrc=mac)  # type: ignore[attr-defined]


def _run_gentle(network, replies=None, *, extra_packets=None, sleep_mock=None, **kwargs):
    """Run scan_network(gentle=True) against a fake sniffer + sendp.

    `replies` maps ip -> mac (or a list of macs, answered in that order):
    when a request for that ip is "sent", the fake sniffer's callback is
    handed the matching ARP replies. Returns
    (devices, ips_requested_in_order).
    """
    replies = replies or {}
    requested: list[str] = []
    _FakeSniffer.events = []
    _FakeSniffer.starts_ok = True

    def fake_sendp(frame, **kw):
        ip = frame["ARP"].pdst
        requested.append(ip)
        _FakeSniffer.events.append("send")
        for packet in extra_packets or []:
            assert _FakeSniffer.last is not None
            _FakeSniffer.last.prn(packet)
        macs = replies.get(ip, [])
        for mac in [macs] if isinstance(macs, str) else macs:
            assert _FakeSniffer.last is not None
            _FakeSniffer.last.prn(_arp_packet(2, ip, mac))

    with (
        mock.patch("scapy.all.AsyncSniffer", _FakeSniffer),
        mock.patch("scapy.all.sendp", fake_sendp),
        mock.patch("time.sleep", sleep_mock or mock.Mock()),
    ):
        devices = scan_network(network, gentle=True, **kwargs)
    return devices, requested


class TestScanNetworkGentleMode:
    """gentle=True: one host at a time, shuffled order, jittered delay -
    see scan_network()'s docstring for why. Replies are collected by one
    background sniffer, so the sweep doesn't wait `timeout` per host."""

    def test_probes_each_host_individually_not_the_whole_range_at_once(self):
        _, requested = _run_gentle("192.168.1.0/30")  # /30 => 2 usable hosts

        assert sorted(requested) == ["192.168.1.1", "192.168.1.2"]

    def test_collects_replies_across_the_separate_requests(self):
        replies = {"192.168.1.1": "aa:aa:aa:aa:aa:aa", "192.168.1.2": "bb:bb:bb:bb:bb:bb"}
        devices, _ = _run_gentle("192.168.1.0/30", replies)

        assert sorted(devices, key=lambda d: d["ip"]) == [
            {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"},
        ]

    def test_silent_hosts_are_not_reported(self):
        devices, requested = _run_gentle("192.168.1.0/30", {"192.168.1.2": "bb:bb:bb:bb:bb:bb"})

        assert len(requested) == 2
        assert devices == [{"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"}]

    def test_order_is_shuffled_not_sequential(self):
        # Replace the shuffle with a deterministic reversal so the test
        # isn't flaky, while still proving the natural .1/.2/.3/... order
        # was changed before probing started.
        with mock.patch("random.shuffle", side_effect=lambda lst: lst.reverse()):
            _, requested = _run_gentle("192.168.1.0/29")  # /29 => 6 usable hosts

        assert requested[0] == "192.168.1.6"  # reversed order => last host probed first

    def test_sleeps_between_hosts_with_a_jittered_not_fixed_delay(self):
        sleep_mock = mock.Mock()
        with mock.patch("random.uniform", return_value=0.02) as mock_uniform:
            _run_gentle(
                "192.168.1.0/30", sleep_mock=sleep_mock, timeout=0.7, jitter_range=(0.01, 0.05)
            )

        # /30 => 2 hosts => exactly one gap between them, drawn from the
        # given jitter range rather than a hardcoded constant, then one
        # final wait for stragglers.
        mock_uniform.assert_called_once_with(0.01, 0.05)
        assert sleep_mock.call_args_list == [mock.call(0.02), mock.call(0.7)]

    def test_total_wait_is_the_jitters_plus_one_timeout_not_a_timeout_per_host(self):
        """Regression for the old design: a blocking srp() per host made a
        sweep cost roughly hosts * timeout."""
        sleep_mock = mock.Mock()
        with mock.patch("random.uniform", return_value=0.02):
            _run_gentle(
                [f"10.0.0.{i}" for i in range(1, 11)],
                sleep_mock=sleep_mock,
                timeout=0.5,
                jitter_range=(0.01, 0.05),
            )

        waits = [call.args[0] for call in sleep_mock.call_args_list]
        assert waits.count(0.5) == 1
        assert sum(waits) == pytest.approx(9 * 0.02 + 0.5)

    def test_a_pre_expanded_host_list_is_used_as_is(self):
        targets = ["10.0.0.5", "10.0.0.9"]
        _, requested = _run_gentle(targets)

        assert set(requested) == set(targets)

    def test_only_arp_replies_for_probed_addresses_are_recorded(self):
        noise = [
            _arp_packet(1, "192.168.1.1", "11:11:11:11:11:11"),  # a request, not a reply
            _arp_packet(2, "192.168.1.200", "22:22:22:22:22:22"),  # not one of our targets
            scapy.Ether() / scapy.IP(),  # type: ignore[attr-defined]  # not ARP at all
        ]
        devices, _ = _run_gentle(
            "192.168.1.0/30", {"192.168.1.2": "bb:bb:bb:bb:bb:bb"}, extra_packets=noise
        )

        assert devices == [{"ip": "192.168.1.2", "mac": "bb:bb:bb:bb:bb:bb"}]

    def test_first_reply_for_an_address_wins(self):
        """srp() matches one answer per request; a second reply for the
        same address (e.g. from a different MAC) must not replace it."""
        replies = {"192.168.1.1": ["aa:aa:aa:aa:aa:aa", "99:99:99:99:99:99"]}
        devices, _ = _run_gentle("192.168.1.0/30", replies)

        assert devices == [{"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}]

    def test_sniffer_runs_before_the_first_request_and_stops_after_the_last(self):
        _run_gentle("192.168.1.0/30")

        assert _FakeSniffer.events == ["start", "send", "send", "stop"]

    def test_sniffer_is_stopped_even_if_sending_fails(self):
        _FakeSniffer.events = []
        _FakeSniffer.starts_ok = True
        with (
            mock.patch("scapy.all.AsyncSniffer", _FakeSniffer),
            mock.patch("scapy.all.sendp", side_effect=OSError("send failed")),
            mock.patch("time.sleep"),
            pytest.raises(OSError, match="send failed"),
        ):
            scan_network("192.168.1.0/30", gentle=True)

        assert _FakeSniffer.events == ["start", "stop"]

    def test_a_sniffer_that_never_starts_is_a_clear_error_not_a_hang(self):
        _FakeSniffer.events = []
        _FakeSniffer.starts_ok = False
        try:
            with (
                mock.patch("scapy.all.AsyncSniffer", _FakeSniffer),
                mock.patch("scapy.all.sendp") as mock_sendp,
                mock.patch("backend.app.scanner.arp_scanner._SNIFFER_START_TIMEOUT", 0.05),
                pytest.raises(RuntimeError, match="did not start"),
            ):
                scan_network("192.168.1.0/30", gentle=True)
        finally:
            _FakeSniffer.starts_ok = True

        mock_sendp.assert_not_called()  # nothing was sent that nobody would hear

    def test_iface_is_used_for_both_sniffing_and_sending(self):
        seen = {}

        def fake_sendp(frame, **kw):
            seen["sendp_iface"] = kw.get("iface")

        _FakeSniffer.events = []
        with (
            mock.patch("scapy.all.AsyncSniffer", _FakeSniffer),
            mock.patch("scapy.all.sendp", fake_sendp),
            mock.patch("time.sleep"),
        ):
            scan_network("192.168.1.0/30", iface="eth9", gentle=True)

        assert seen["sendp_iface"] == "eth9"
        assert _FakeSniffer.last is not None
        assert _FakeSniffer.last.kwargs["iface"] == "eth9"
