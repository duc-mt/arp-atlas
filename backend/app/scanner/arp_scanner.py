"""ARP network scanner — validates network strings and performs ARP sweeps."""

from __future__ import annotations

import ipaddress
from typing import Any

from backend.app.config import DEFAULT_TIMEOUT


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


def scan_network(
    network: str | list[str],
    timeout: float = DEFAULT_TIMEOUT,
    iface: str | None = None,
) -> list[dict[str, Any]]:
    """Send an ARP broadcast to `network` and collect the replies.

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

    Returns
    -------
    list[dict]
        One {"ip": ..., "mac": ...} dict per device that replied.
    """
    import scapy.all as scapy  # type: ignore[import-untyped]

    arp_request = scapy.ARP(pdst=network)  # type: ignore[attr-defined]
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # type: ignore[attr-defined]
    arp_broadcast = broadcast / arp_request

    answered, _unanswered = scapy.srp(
        arp_broadcast, timeout=timeout, verbose=False, iface=iface
    )

    devices = []
    for packet in answered:
        ip = packet[1].psrc
        mac = packet[1].hwsrc
        devices.append({"ip": ip, "mac": mac})
    return devices
