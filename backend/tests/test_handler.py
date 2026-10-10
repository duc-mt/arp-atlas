from __future__ import annotations
"""
==============================================================================
Module Name:   test_handler.py
Description:   Implementation and logic for test_handler.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_handler.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

"""Tests for backend.app.server.handler - previously 0% covered.

_parse_target() and _get_netmask() are pure functions and tested
directly. The POST/GET endpoints are tested against a real server
bound to an ephemeral localhost port (scapy.srp() mocked out, same
convention as the rest of the suite) rather than by poking at
BaseHTTPRequestHandler internals directly.
"""

import http.client
import json
import threading
from unittest import mock

import pytest

from backend.app.server.handler import (
    MAX_RANGE_SIZE,
    DashboardHandler,
    ReuseTCPServer,
    _get_netmask,
    _parse_target,
)


class TestParseTarget:
    def test_plain_cidr_expands_to_host_ips(self):
        ips, network_str = _parse_target("192.168.1.0/30")
        assert ips == ["192.168.1.1", "192.168.1.2"]
        assert network_str == "192.168.1.0/30"

    def test_single_ip_range_includes_both_ends(self):
        ips, network_str = _parse_target("192.168.1.10-192.168.1.12")
        assert ips == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        assert network_str == "192.168.1.10-192.168.1.12"

    def test_reversed_range_is_normalised_low_to_high(self):
        ips, network_str = _parse_target("192.168.1.12-192.168.1.10")
        assert ips == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        assert network_str == "192.168.1.10-192.168.1.12"

    def test_range_at_exactly_the_cap_is_accepted(self):
        ips, _ = _parse_target("10.0.0.0-10.0.255.255")
        assert len(ips) == MAX_RANGE_SIZE == 65536

    def test_range_over_the_cap_is_rejected(self):
        """Regression test for the DoS fix: an oversized range used to
        build a multi-million-entry Python list before a single ARP
        packet went out. It should now fail fast with a clear error."""
        with pytest.raises(ValueError, match="too large"):
            _parse_target("10.0.0.0-10.1.0.0")  # 65,537 addresses

    def test_oversized_plain_cidr_is_also_rejected(self):
        with pytest.raises(ValueError, match="too large"):
            _parse_target("10.0.0.0/8")


class TestGetNetmask:
    def test_uses_ip_addr_show_when_available(self):
        """iproute2's `ip` is the primary path - it's present on
        current Linux distros that no longer ship ifconfig."""
        ip_json_output = json.dumps(
            [{"addr_info": [{"family": "inet6", "prefixlen": 64}, {"family": "inet", "prefixlen": 27}]}]
        ).encode()
        with mock.patch("backend.app.server.handler.shutil.which", return_value="/usr/sbin/ip"), \
             mock.patch("backend.app.server.handler.subprocess.check_output", return_value=ip_json_output):
            assert _get_netmask("eth0") == 27

    def test_falls_back_to_ifconfig_decimal_mask_when_ip_missing(self):
        ifconfig_output = (
            b"eth0: flags=4163  inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        )

        def which(name: str) -> str | None:
            return None if name == "ip" else "/sbin/ifconfig"

        with mock.patch("backend.app.server.handler.shutil.which", side_effect=which), \
             mock.patch("backend.app.server.handler.subprocess.check_output", return_value=ifconfig_output):
            assert _get_netmask("eth0") == 24

    def test_falls_back_to_ifconfig_hex_mask(self):
        ifconfig_output = b"eth0: flags=... inet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255\n"

        def which(name: str) -> str | None:
            return None if name == "ip" else "/sbin/ifconfig"

        with mock.patch("backend.app.server.handler.shutil.which", side_effect=which), \
             mock.patch("backend.app.server.handler.subprocess.check_output", return_value=ifconfig_output):
            assert _get_netmask("eth0") == 24

    def test_defaults_to_24_when_nothing_works(self):
        with mock.patch("backend.app.server.handler.shutil.which", return_value=None), \
             mock.patch("backend.app.server.handler.subprocess.check_output", side_effect=FileNotFoundError):
            assert _get_netmask("eth0") == 24


@pytest.fixture
def live_server():
    """A real DashboardHandler server on an ephemeral localhost port."""
    httpd = ReuseTCPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address
    finally:
        httpd.shutdown()
        thread.join(timeout=2)
        httpd.server_close()


def _post_json(host: str, port: int, path: str, payload: dict) -> tuple[int, dict]:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        body = json.dumps(payload)
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read())
    finally:
        conn.close()


class TestScanEndpoint:
    def test_oversized_range_is_rejected_with_a_clean_error_not_a_hang(self, live_server, tmp_path):
        """End-to-end version of the DoS regression test above - confirms
        the cap is actually enforced on the request path, not just in
        the unit-level call to _parse_target()."""
        host, port = live_server
        with mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")):
            status, payload = _post_json(host, port, "/api/scan", {"target": "10.0.0.0-10.1.0.0"})

        assert status == 500
        assert payload["status"] == "error"
        assert "too large" in payload["message"]

    def test_successful_scan_is_persisted_to_history(self, live_server, tmp_path):
        host, port = live_server
        history_path = tmp_path / "scan_history.json"
        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)), \
             mock.patch("scapy.all.srp", return_value=([], [])):
            status, payload = _post_json(host, port, "/api/scan", {"target": "192.168.50.0/30"})

        assert status == 200
        assert payload["status"] == "success"
        assert history_path.exists()

    def test_unknown_path_returns_404(self, live_server):
        host, port = live_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/nope")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 404


class TestClearAndHistoryEndpoints:
    def test_clear_removes_the_history_file(self, live_server, tmp_path):
        host, port = live_server
        history_path = tmp_path / "scan_history.json"
        history_path.write_text("{}")

        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)):
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/api/clear")
            resp = conn.getresponse()
            payload = json.loads(resp.read())
            conn.close()

        assert resp.status == 200
        assert payload["status"] == "success"
        assert not history_path.exists()

    def test_history_endpoint_404s_when_no_scan_has_run_yet(self, live_server, tmp_path):
        host, port = live_server
        with mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")):
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/scan_history.json")
            resp = conn.getresponse()
            resp.read()
            conn.close()

        assert resp.status == 404

    def test_history_endpoint_serves_saved_history(self, live_server, tmp_path):
        host, port = live_server
        history_path = tmp_path / "scan_history.json"
        history_path.write_text(json.dumps({"192.168.1.0/24": {"devices": []}}))

        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)):
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/scan_history.json")
            resp = conn.getresponse()
            payload = json.loads(resp.read())
            conn.close()

        assert resp.status == 200
        assert payload == {"192.168.1.0/24": {"devices": []}}


class TestDashboardPage:
    def test_get_root_serves_html_with_interface_options(self, live_server):
        host, port = live_server
        fake_iface = mock.Mock(name="eth0")
        fake_iface.name = "eth0"
        fake_iface.ip = "192.168.1.5"

        with mock.patch("scapy.all.get_working_ifaces", return_value=[fake_iface]), \
             mock.patch("backend.app.server.handler._get_netmask", return_value=24):
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()

        assert resp.status == 200
        assert "eth0" in body
        assert "192.168.1.5" in body
