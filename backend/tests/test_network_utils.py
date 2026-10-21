"""
==============================================================================
Module Name:   test_network_utils.py
Description:   Tests for get_default_gateway().
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         pytest backend/tests/test_network_utils.py
Notes:         Requires Python 3.10+
==============================================================================
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from backend.app.services.network_utils import get_default_gateway


def _route(net: int, mask: int, gateway: str, iface: str) -> tuple:
    """(net, mask, gw, iface, addr, metric) like scapy's routing table."""
    return (net, mask, gateway, SimpleNamespace(name=iface), "192.168.1.5", 100)


def _with_routes(routes: list):
    return mock.patch("scapy.all.conf.route", SimpleNamespace(routes=routes))


def test_finds_the_default_route_gateway() -> None:
    routes = [
        _route(0xC0A80100, 0xFFFFFF00, "0.0.0.0", "eth0"),
        _route(0, 0, "192.168.1.1", "eth0"),
    ]
    with _with_routes(routes):
        assert get_default_gateway() == "192.168.1.1"


def test_only_considers_the_requested_interface() -> None:
    routes = [_route(0, 0, "10.9.0.1", "tun0"), _route(0, 0, "192.168.1.1", "eth0")]
    with _with_routes(routes):
        assert get_default_gateway("eth0") == "192.168.1.1"
        assert get_default_gateway("tun0") == "10.9.0.1"
        assert get_default_gateway("wlan9") is None


def test_an_on_link_default_route_has_no_gateway() -> None:
    with _with_routes([_route(0, 0, "0.0.0.0", "tun0")]):
        assert get_default_gateway() is None


def test_a_non_default_route_is_not_a_gateway() -> None:
    with _with_routes([_route(0x0A000000, 0xFF000000, "192.168.1.254", "eth0")]):
        assert get_default_gateway() is None


def test_no_routes() -> None:
    with _with_routes([]):
        assert get_default_gateway() is None


def test_an_unreadable_routing_table_returns_none_instead_of_raising() -> None:
    class Broken:
        @property
        def routes(self) -> list:
            raise OSError("cannot read routing table")

    with mock.patch("scapy.all.conf.route", Broken()):
        assert get_default_gateway() is None
