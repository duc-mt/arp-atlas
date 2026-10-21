"""
==============================================================================
Module Name:   network_utils.py
Description:   Small helpers for reading the local routing table via scapy.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         from backend.app.services.network_utils import get_default_gateway
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations


def get_default_gateway(iface: str | None = None) -> str | None:
    """The IPv4 default gateway, or None if there isn't one.

    Parameters
    ----------
    iface : str or None
        Only consider default routes out of this interface. None accepts
        the first default route found.

    Returns None - never raises - if scapy can't read the routing table
    or the only default route is on-link (gateway 0.0.0.0, e.g. a VPN).
    """
    try:
        import scapy.all as scapy  # type: ignore[import-untyped]

        routes = scapy.conf.route.routes
    except Exception:
        return None

    for entry in routes:
        net, mask, gateway, route_iface = entry[0], entry[1], entry[2], entry[3]
        if net != 0 or mask != 0:  # not the default route
            continue
        name = route_iface.name if hasattr(route_iface, "name") else str(route_iface)
        if iface is not None and name != iface:
            continue
        if gateway and gateway != "0.0.0.0":  # nosec B104 - comparing, not binding
            return str(gateway)
    return None
