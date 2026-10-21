"""
==============================================================================
Module Name:   test_raw_socket_integration.py
Description:   Real-socket tests of the scapy code paths (the ARP sweeps and
               the SYN scan) over the loopback interface, with no mocks.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         sudo pytest backend/tests/test_raw_socket_integration.py
Notes:         Requires Python 3.10+, Linux, raw-socket privileges (root or
               CAP_NET_RAW) and a loopback interface named "lo". Skipped
               everywhere else - e.g. unprivileged CI - where the mocked
               tests in test_scan_network.py and test_port_scan.py still
               cover the logic. The mocks can't catch scapy API drift;
               these can.
==============================================================================
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from backend.app.scanner.arp_scanner import scan_network
from backend.app.scanner.classifier import scan_device_ports


def _raw_sockets_available() -> bool:
    try:
        af_packet = getattr(socket, "AF_PACKET", None)
        if af_packet is None:
            return False
        socket.socket(af_packet, socket.SOCK_RAW, socket.htons(3)).close()
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW).close()
        return "lo" in {name for _, name in socket.if_nameindex()}
    except (AttributeError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _raw_sockets_available(), reason="needs Linux, raw-socket privileges and a 'lo' interface"
)

_ANSWERING = {"10.99.0.1": "aa:bb:cc:00:00:01", "10.99.0.3": "aa:bb:cc:00:00:03"}


@pytest.fixture
def arp_responder() -> Iterator[None]:
    """Answers ARP requests for _ANSWERING's addresses on loopback, the way
    two real hosts on a LAN would."""
    import scapy.all as scapy  # type: ignore[import-untyped]

    def respond(packet: Any) -> None:
        if not packet.haslayer(scapy.ARP) or packet[scapy.ARP].op != 1:  # type: ignore[attr-defined]
            return
        ip = packet[scapy.ARP].pdst  # type: ignore[attr-defined]
        if ip in _ANSWERING:
            reply = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(  # type: ignore[attr-defined]
                op=2, psrc=ip, hwsrc=_ANSWERING[ip], pdst="10.99.0.254"
            )
            scapy.sendp(reply, iface="lo", verbose=False)

    started = threading.Event()
    sniffer = scapy.AsyncSniffer(iface="lo", prn=respond, store=False, started_callback=started.set)
    sniffer.start()
    assert started.wait(5), "the fake ARP responder never started"
    try:
        yield
    finally:
        sniffer.stop()


def _targets(count: int) -> list[str]:
    return [f"10.99.0.{i}" for i in range(1, count + 1)]


@pytest.mark.usefixtures("arp_responder")
class TestArpSweepsOverLoopback:
    def test_gentle_sweep_finds_exactly_the_answering_hosts(self) -> None:
        devices = scan_network(
            _targets(10), timeout=0.5, iface="lo", gentle=True, jitter_range=(0.01, 0.02)
        )

        assert {d["ip"]: d["mac"] for d in devices} == _ANSWERING

    def test_gentle_sweep_does_not_wait_a_timeout_per_host(self) -> None:
        """The old design blocked for `timeout` after every request, so ten
        hosts took 10 * 0.5s = 5s+; replies are now collected by one sniffer."""
        start = time.perf_counter()
        scan_network(_targets(10), timeout=0.5, iface="lo", gentle=True, jitter_range=(0.01, 0.02))

        assert time.perf_counter() - start < 4.0

    def test_normal_sweep_with_retries_finds_the_same_hosts(self) -> None:
        devices = scan_network(_targets(10), timeout=0.5, iface="lo", retries=1)

        assert {d["ip"]: d["mac"] for d in devices} == _ANSWERING


class TestSynScanOverLoopback:
    @staticmethod
    def _listener() -> tuple[socket.socket, int]:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)

        def accept_forever() -> None:
            try:
                while True:
                    srv.accept()[0].close()
            except OSError:
                pass

        threading.Thread(target=accept_forever, daemon=True).start()
        return srv, int(srv.getsockname()[1])

    def test_open_ports_are_found_and_closed_ones_are_not(self) -> None:
        srv_a, port_a = self._listener()
        srv_b, port_b = self._listener()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = int(probe.getsockname()[1])
        try:
            result = scan_device_ports(
                "127.0.0.1", [port_b, closed, port_a], timeout=1.0, method="syn"
            )
        finally:
            srv_a.close()
            srv_b.close()

        assert result == [port_b, port_a]  # open ports only, in the order given

    def test_matches_the_connect_scan(self) -> None:
        srv, port = self._listener()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = int(probe.getsockname()[1])
        try:
            ports = [closed, port]
            assert scan_device_ports("127.0.0.1", ports, 1.0, method="syn") == scan_device_ports(
                "127.0.0.1", ports, 1.0, method="connect"
            )
        finally:
            srv.close()
