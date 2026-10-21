"""
==============================================================================
Module Name:   arp_scanner.py
Description:   Source module arp_scanner.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 arp_scanner.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from typing import Any

from backend.app.config import DEFAULT_ARP_RETRIES, DEFAULT_TIMEOUT, GENTLE_SCAN_JITTER

# How long to wait for the background ARP sniffer to come up before giving
# up on a gentle sweep (it fails to start on e.g. a permissions error, and
# the error is raised in its own thread where nothing would see it).
_SNIFFER_START_TIMEOUT = 5.0


def validate_network(network: str) -> str:
    """Validate and normalise a user-supplied network address.

    Parameters
    ----------
    network : str
        The raw string typed by the user, e.g. "192.168.1.0/24".

    Returns
    -------
    str
        The normalised CIDR string.

    Raises
    ------
    ValueError
        If the input isn't a valid IP address or network, once
        whitespace has been stripped.
    """
    # NOTE: this used to feed the raw, un-stripped input straight into
    # ipaddress.ip_network(). A pasted address with a trailing newline
    # or leading space (an extremely common paste artifact) is a
    # perfectly valid address once trimmed, but was rejected outright.
    network = network.strip()

    # NOTE: ip_network() defaults to strict=True, which rejects any
    # address with host bits set relative to its prefix - e.g.
    # "192.168.1.5/24" (a natural way to type "scan the subnet this
    # host is on") was rejected with "has host bits set", even though
    # the intent is unambiguous and scapy's own address expansion
    # already normalises it down to the containing network correctly.
    # strict=False accepts it, matching what actually gets scanned.
    net = ipaddress.ip_network(network, strict=False)

    return str(net)


def _expand_hosts(network: str) -> list[str]:
    """Expand a CIDR network into its individual host addresses (the
    network and broadcast addresses are excluded, same as scapy's own
    ARP sweep effectively treats them)."""
    return [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]


def scan_network(
    network: str | list[str],
    timeout: float = DEFAULT_TIMEOUT,
    iface: str | None = None,
    *,
    gentle: bool = False,
    jitter_range: tuple[float, float] = GENTLE_SCAN_JITTER,
    retries: int = DEFAULT_ARP_RETRIES,
) -> list[dict[str, Any]]:
    """Send ARP requests to `network` and collect the replies.

    Parameters
    ----------
    network : str | list[str]
        The network/address to scan, e.g. "192.168.1.0/24", or a
        pre-expanded list of individual IP strings.
    timeout : float
        Seconds to wait for ARP replies.
    iface : str | None
        Network interface to bind to (e.g. "en0"). None = let scapy
        choose.
    gentle : bool
        If False (default), send one broadcast covering the whole
        range in a single `scapy.srp()` call - fastest, but puts all
        the ARP traffic on the wire at once. If True, probe hosts one
        at a time, in randomised order, with a small random delay
        between each - friendlier to switches/monitoring tuned to flag
        a burst of broadcasts as a storm or a sequential sweep as
        suspicious. Requests are paced by the jitter alone while one
        background sniffer collects replies, so the sweep takes roughly
        the sum of the jitters plus one `timeout` - it does not wait a
        full `timeout` per host.
    jitter_range : tuple[float, float]
        (min, max) seconds to randomly wait between hosts in gentle
        mode. Ignored when `gentle` is False.
    retries : int
        How many times the normal (non-gentle) sweep re-sends requests
        that got no reply; each retry costs one more `timeout` window
        while hosts are still unanswered. 0 sends each request once.
        Ignored in gentle mode, which would otherwise re-probe nearly
        every host and defeat the point of pacing.

    Returns
    -------
    list[dict]
        One {"ip": ..., "mac": ...} dict per device that replied.
    """
    import scapy.all as scapy  # type: ignore[import-untyped]

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # type: ignore[attr-defined]

    if not gentle:
        arp_request = scapy.ARP(pdst=network)  # type: ignore[attr-defined]
        answered, _unanswered = scapy.srp(
            broadcast / arp_request,
            timeout=timeout,
            retry=retries,
            verbose=False,
            iface=iface,
        )
        return [{"ip": packet[1].psrc, "mac": packet[1].hwsrc} for packet in answered]

    targets = list(network) if isinstance(network, list) else _expand_hosts(network)
    random.shuffle(targets)  # nosec B311 - scan pacing/ordering, not a security control
    return _gentle_sweep(scapy, broadcast, targets, timeout, iface, jitter_range)


def _gentle_sweep(
    scapy: Any,
    broadcast: Any,
    targets: list[str],
    timeout: float,
    iface: str | None,
    jitter_range: tuple[float, float],
) -> list[dict[str, Any]]:
    """Send one ARP request per target, `jitter_range` apart, while a
    background sniffer records the replies.

    Doing the waiting in a sniffer rather than in a blocking `srp()` per
    host is what keeps the sweep from costing `timeout` seconds per
    address. Returns one dict per address that answered, in arrival
    order; a second reply for the same address (from another MAC) is
    ignored, like `srp()` which matches one answer per request.
    """
    wanted = set(targets)
    replies: dict[str, str] = {}

    def record(packet: Any) -> None:
        if not packet.haslayer(scapy.ARP):
            return
        arp = packet[scapy.ARP]
        if arp.op == 2 and arp.psrc in wanted and arp.psrc not in replies:  # 2 = is-at (reply)
            replies[arp.psrc] = arp.hwsrc

    started = threading.Event()
    sniffer = scapy.AsyncSniffer(iface=iface, prn=record, store=False, started_callback=started.set)
    sniffer.start()
    try:
        if not started.wait(_SNIFFER_START_TIMEOUT):
            raise RuntimeError("the ARP reply sniffer did not start (raw-socket permissions?)")
        last_index = len(targets) - 1
        for index, ip in enumerate(targets):
            scapy.sendp(broadcast / scapy.ARP(pdst=ip), iface=iface, verbose=False)
            if index != last_index:
                time.sleep(random.uniform(*jitter_range))  # nosec B311 - pacing delay
        time.sleep(timeout)  # let the last replies come in
    finally:
        if sniffer.running:
            sniffer.stop()
    return [{"ip": ip, "mac": mac} for ip, mac in replies.items()]
