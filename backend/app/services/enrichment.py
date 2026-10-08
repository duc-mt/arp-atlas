"""Device enrichment — vendor (OUI) and hostname (reverse DNS) lookups."""

from __future__ import annotations

import asyncio
import socket
from typing import Any


def is_mac_randomized(mac: str) -> bool:
    """Return True if the MAC address's locally-administered bit is set
    (i.e. it is likely a randomised/privacy MAC rather than a
    hardware-burned OUI).
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def lookup_vendor(mac: str) -> str | None:
    """Look up the manufacturer that registered a MAC address's OUI.

    Uses scapy's own bundled IEEE manufacturer database
    (`scapy.conf.manufdb`) — no extra dependency and no network lookup.

    Parameters
    ----------
    mac : str
        A MAC address, e.g. "9c:5a:6b:1e:4f:0c".

    Returns
    -------
    str or None
        The manufacturer name, or None if the OUI isn't in the
        database (very common for locally-administered/randomised
        MACs).
    """
    import scapy.all as scapy  # type: ignore[import-untyped]

    vendor = scapy.conf.manufdb._get_manuf(mac)
    # _get_manuf() echoes the input back unchanged when there's no
    # match, rather than raising or returning None itself.
    if vendor.lower() == mac.lower():
        return None
    return vendor


async def _lookup_hostname_async(ip: str, timeout: float) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getnameinfo, (ip, 0), socket.NI_NAMEREQD),
            timeout=timeout,
        )
        return res[0]
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return None


def lookup_hostname(ip: str, timeout: float = 0.3) -> str | None:
    """Attempt a reverse DNS lookup for an IP address.

    Parameters
    ----------
    ip : str
        The IP address to resolve.
    timeout : float
        Seconds to wait before giving up on this one lookup.

    Returns
    -------
    str or None
        The resolved hostname, or None if there's no PTR record, the
        lookup times out, or DNS is unreachable.
    """
    try:
        return asyncio.run(_lookup_hostname_async(ip, timeout))
    except RuntimeError:
        # Fallback if already in an event loop or loop is closed
        return None


async def _enrich_devices_async(devices: list[dict[str, Any]]) -> None:
    sem = asyncio.Semaphore(50)

    async def _bounded_lookup(ip: str, timeout: float) -> str | None:
        async with sem:
            return await _lookup_hostname_async(ip, timeout)

    tasks = [_bounded_lookup(d["ip"], 0.3) for d in devices]
    hostnames = await asyncio.gather(*tasks)
    for d, h in zip(devices, hostnames, strict=False):
        d["hostname"] = h


def enrich_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add "vendor" and "hostname" fields to each device dict in place.

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network().

    Returns
    -------
    list[dict]
        The same list, for convenient chaining — each dict has been
        mutated in place, not replaced.
    """
    for device in devices:
        device["vendor"] = lookup_vendor(device["mac"])
        device["is_randomized"] = is_mac_randomized(device["mac"])

    if devices:
        asyncio.run(_enrich_devices_async(devices))

    return devices
