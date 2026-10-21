"""
==============================================================================
Module Name:   test_handler.py
Description:   Source module test_handler.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 test_handler.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from unittest import mock

import pytest

from backend.app.config import DEFAULT_ARP_RETRIES, DEFAULT_TIMEOUT
from backend.app.server.handler import (
    MAX_RANGE_SIZE,
    SCAN_STATE,
    DashboardHandler,
    ReuseTCPServer,
    ScanOptions,
    ScanState,
    _get_netmask,
    _parse_options,
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
            [
                {
                    "addr_info": [
                        {"family": "inet6", "prefixlen": 64},
                        {"family": "inet", "prefixlen": 27},
                    ]
                }
            ]
        ).encode()
        with (
            mock.patch("backend.app.server.handler.shutil.which", return_value="/usr/sbin/ip"),
            mock.patch(
                "backend.app.server.handler.subprocess.check_output", return_value=ip_json_output
            ),
        ):
            assert _get_netmask("eth0") == 27

    def test_falls_back_to_ifconfig_decimal_mask_when_ip_missing(self):
        ifconfig_output = (
            b"eth0: flags=4163  inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        )

        def which(name: str) -> str | None:
            return None if name == "ip" else "/sbin/ifconfig"

        with (
            mock.patch("backend.app.server.handler.shutil.which", side_effect=which),
            mock.patch(
                "backend.app.server.handler.subprocess.check_output", return_value=ifconfig_output
            ),
        ):
            assert _get_netmask("eth0") == 24

    def test_falls_back_to_ifconfig_hex_mask(self):
        ifconfig_output = b"eth0: flags=... inet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255\n"

        def which(name: str) -> str | None:
            return None if name == "ip" else "/sbin/ifconfig"

        with (
            mock.patch("backend.app.server.handler.shutil.which", side_effect=which),
            mock.patch(
                "backend.app.server.handler.subprocess.check_output", return_value=ifconfig_output
            ),
        ):
            assert _get_netmask("eth0") == 24

    def test_defaults_to_24_when_nothing_works(self):
        with (
            mock.patch("backend.app.server.handler.shutil.which", return_value=None),
            mock.patch(
                "backend.app.server.handler.subprocess.check_output", side_effect=FileNotFoundError
            ),
        ):
            assert _get_netmask("eth0") == 24


@pytest.fixture
def live_server():
    """A real DashboardHandler server on an ephemeral localhost port."""
    httpd = ReuseTCPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
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
        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(history_path)),
            mock.patch("scapy.all.srp", return_value=([], [])),
        ):
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

        with (
            mock.patch("scapy.all.get_working_ifaces", return_value=[fake_iface]),
            mock.patch("backend.app.server.handler._get_netmask", return_value=24),
        ):
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()

        assert resp.status == 200
        assert "eth0" in body
        assert "192.168.1.5" in body


def _request(server, method, path, *, headers=None, body=None):
    """One request against the live server -> (status, parsed-or-raw body)."""
    host, port = server
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        try:
            return resp.status, json.loads(raw)
        except ValueError:
            return resp.status, raw
    finally:
        conn.close()


def _post(server, path, payload):
    host, port = server
    return _post_json(host, port, path, payload)


class TestRequestGuards:
    """A page open in another tab must not be able to drive this server:
    POST /api/scan runs as the (usually root) user who started it and
    /api/clear deletes the history."""

    def test_cross_origin_clear_is_refused_and_the_history_survives(self, live_server, tmp_path):
        history_path = tmp_path / "scan_history.json"
        history_path.write_text("{}")
        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)):
            status, payload = _request(
                live_server, "POST", "/api/clear", headers={"Origin": "http://evil.example"}
            )

        assert status == 403
        assert payload["message"] == "forbidden"
        assert history_path.exists()

    def test_cross_origin_scan_is_refused_without_scanning(self, live_server):
        with mock.patch("backend.app.scanner.arp_scanner.scan_network") as mock_scan:
            status, _ = _request(
                live_server,
                "POST",
                "/api/scan",
                headers={"Origin": "http://evil.example", "Content-Type": "application/json"},
                body=json.dumps({"target": "192.168.50.0/30"}),
            )

        assert status == 403
        mock_scan.assert_not_called()

    def test_origin_null_is_refused(self, live_server):
        status, _ = _request(live_server, "POST", "/api/clear", headers={"Origin": "null"})
        assert status == 403

    def test_a_different_local_port_is_a_different_origin(self, live_server):
        host, port = live_server
        status, _ = _request(
            live_server, "POST", "/api/clear", headers={"Origin": f"http://{host}:{port + 1}"}
        )
        assert status == 403

    def test_the_dashboards_own_origin_is_accepted(self, live_server, tmp_path):
        host, port = live_server
        with mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")):
            status, _ = _request(
                live_server, "POST", "/api/clear", headers={"Origin": f"http://{host}:{port}"}
            )
        assert status == 200

    def test_a_cross_site_fetch_is_refused(self, live_server):
        status, _ = _request(
            live_server, "POST", "/api/clear", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert status == 403

    def test_a_same_origin_fetch_is_accepted(self, live_server, tmp_path):
        with mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")):
            status, _ = _request(
                live_server, "POST", "/api/clear", headers={"Sec-Fetch-Site": "same-origin"}
            )
        assert status == 200

    def test_a_foreign_host_header_is_refused_on_get_too(self, live_server, tmp_path):
        """DNS rebinding: the browser sends the attacker's hostname."""
        history_path = tmp_path / "scan_history.json"
        history_path.write_text('{"x": {"devices": []}}')
        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)):
            status, _ = _request(
                live_server, "GET", "/scan_history.json", headers={"Host": "rebind.example:8080"}
            )
        assert status == 403

    def test_localhost_is_an_accepted_host_name(self, live_server, tmp_path):
        _, port = live_server
        history_path = tmp_path / "scan_history.json"
        history_path.write_text('{"x": {"devices": []}}')
        with mock.patch("backend.app.config.HISTORY_FILE", str(history_path)):
            status, _ = _request(
                live_server, "GET", "/scan_history.json", headers={"Host": f"localhost:{port}"}
            )
        assert status == 200

    def test_scan_requires_a_json_content_type(self, live_server):
        """A text/plain body is the one kind of cross-site POST that needs
        no CORS preflight, so refuse it even if the Origin check is bypassed."""
        with mock.patch("backend.app.scanner.arp_scanner.scan_network") as mock_scan:
            status, payload = _request(
                live_server,
                "POST",
                "/api/scan",
                headers={"Content-Type": "text/plain"},
                body=json.dumps({"target": "192.168.50.0/30"}),
            )

        assert status == 415
        assert "application/json" in payload["message"]
        mock_scan.assert_not_called()

    def test_a_charset_suffix_on_the_json_content_type_is_fine(self, live_server, tmp_path):
        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")),
            mock.patch("scapy.all.srp", return_value=([], [])),
        ):
            status, _ = _request(
                live_server,
                "POST",
                "/api/scan",
                headers={"Content-Type": "application/json; charset=utf-8"},
                body=json.dumps({"target": "192.168.50.0/30"}),
            )
        assert status == 200


class TestScanState:
    def test_idle_snapshot(self):
        assert ScanState().snapshot() == {"scanning": False}

    def test_only_one_scan_may_begin(self):
        state = ScanState()
        assert state.try_begin() is True
        assert state.try_begin() is False
        state.end()
        assert state.try_begin() is True

    def test_snapshot_tracks_phase_and_port_progress(self):
        state = ScanState()
        state.try_begin()
        assert state.snapshot()["phase"] == "starting"
        state.set_phase("ports")
        state.progress(3, 10)
        snap = state.snapshot()
        assert (snap["scanning"], snap["phase"]) == (True, "ports")
        assert (snap["ports_done"], snap["ports_total"]) == (3, 10)
        assert snap["elapsed"] >= 0
        state.end()
        assert state.snapshot() == {"scanning": False}


class TestScanLockAndStatus:
    def test_status_is_idle_when_nothing_is_running(self, live_server):
        assert _request(live_server, "GET", "/api/status") == (200, {"scanning": False})

    def test_a_running_scan_does_not_block_the_server_and_a_second_scan_gets_409(
        self, live_server, tmp_path
    ):
        """The server used to be single-threaded: the whole dashboard hung
        for the length of a scan, and a second click queued up behind it."""
        release = threading.Event()
        started = threading.Event()

        def slow_srp(*args, **kwargs):
            started.set()
            assert release.wait(10)
            return [], []

        outcome: dict = {}

        def first_scan():
            outcome["first"] = _request(
                live_server,
                "POST",
                "/api/scan",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"target": "192.168.50.0/30"}),
            )

        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")),
            mock.patch("scapy.all.srp", slow_srp),
        ):
            worker = threading.Thread(target=first_scan, daemon=True)
            worker.start()
            try:
                assert started.wait(5), "the scan never reached the ARP sweep"

                # served while the scan is still running
                status, snap = _request(live_server, "GET", "/api/status")
                assert status == 200
                assert snap["scanning"] is True
                assert snap["phase"] == "arp"

                status, payload = _request(
                    live_server,
                    "POST",
                    "/api/scan",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"target": "192.168.50.0/30"}),
                )
                assert status == 409
                assert "already running" in payload["message"]
            finally:
                release.set()
                worker.join(timeout=10)

        assert outcome["first"][0] == 200
        assert _request(live_server, "GET", "/api/status") == (200, {"scanning": False})

    def test_a_failed_scan_releases_the_lock(self, live_server, tmp_path):
        with mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")):
            status, _ = _post(live_server, "/api/scan", {"target": "10.0.0.0-10.1.0.0"})
        assert status == 500
        assert SCAN_STATE.snapshot() == {"scanning": False}
        assert SCAN_STATE.try_begin() is True  # and a new scan can start
        SCAN_STATE.end()

    def test_port_scan_progress_reaches_the_status_snapshot(self, live_server, tmp_path):
        seen = {}

        def fake_scan_ports(devices, **kwargs):
            kwargs["progress_callback"](2, 5, devices[0])
            seen.update(SCAN_STATE.snapshot())
            return devices

        device = {"ip": "192.168.50.1", "mac": "aa:aa:aa:aa:aa:aa"}
        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")),
            mock.patch("backend.app.scanner.arp_scanner.scan_network", return_value=[device]),
            mock.patch("backend.app.services.enrichment.enrich_devices"),
            mock.patch("backend.app.scanner.classifier.scan_devices_ports", fake_scan_ports),
        ):
            status, _ = _post(
                live_server, "/api/scan", {"target": "192.168.50.0/30", "scan_ports": True}
            )

        assert status == 200
        assert (seen["phase"], seen["ports_done"], seen["ports_total"]) == ("ports", 2, 5)

    def test_progress_accepts_the_three_arguments_the_real_scanner_passes(self):
        """Regression: progress() used to take two, and scan_devices_ports()
        calls progress_callback(count, total, device) - so every dashboard
        port scan died with a TypeError after its first device."""
        state = ScanState()
        state.try_begin()
        devices = [{"ip": "192.168.50.1", "mac": "aa"}, {"ip": "192.168.50.2", "mac": "bb"}]
        with mock.patch("backend.app.scanner.classifier.scan_device_ports", return_value=[]):
            from backend.app.scanner.classifier import scan_devices_ports

            scan_devices_ports(devices, progress_callback=state.progress)
        snap = state.snapshot()
        assert (snap["ports_done"], snap["ports_total"]) == (2, 2)
        state.end()


class TestParseOptions:
    def test_defaults(self):
        assert _parse_options({}) == ScanOptions()
        defaults = ScanOptions()
        assert defaults.timeout == DEFAULT_TIMEOUT
        assert defaults.retries == DEFAULT_ARP_RETRIES
        assert (defaults.gentle, defaults.ports, defaults.snmp) == (False, None, False)

    def test_blank_values_mean_default(self):
        assert _parse_options({"timeout": "", "retries": None, "ports": "  "}) == ScanOptions()

    def test_all_options(self):
        options = _parse_options(
            {
                "scan_ports": True,
                "ports": "22,8000-8002",
                "snmp": True,
                "gentle": True,
                "timeout": "2.5",
                "retries": 3,
            }
        )
        assert options == ScanOptions(
            timeout=2.5, retries=3, gentle=True, ports=[22, 8000, 8001, 8002], snmp=True
        )

    def test_ports_and_snmp_are_ignored_unless_scan_ports_is_on(self):
        options = _parse_options({"ports": "22", "snmp": True})
        assert options.ports is None
        assert options.snmp is False

    @pytest.mark.parametrize(
        ("data", "message"),
        [
            ({"timeout": "abc"}, "timeout must be a number"),
            ({"timeout": 0}, "between 0.1 and 30"),
            ({"timeout": 31}, "between 0.1 and 30"),
            ({"retries": "x"}, "retries must be a whole number"),
            ({"retries": -1}, "between 0 and 5"),
            ({"retries": 6}, "between 0 and 5"),
            ({"scan_ports": True, "ports": "22,,80"}, "ports: empty entry"),
            ({"scan_ports": True, "ports": "70000"}, "ports: port 70000"),
        ],
    )
    def test_invalid_values_raise_a_readable_error(self, data, message):
        with pytest.raises(ValueError, match=message):
            _parse_options(data)


class TestScanOptionsEndToEnd:
    def _scan(self, live_server, tmp_path, payload):
        device = {"ip": "192.168.50.1", "mac": "aa:aa:aa:aa:aa:aa"}
        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(tmp_path / "scan_history.json")),
            mock.patch(
                "backend.app.scanner.arp_scanner.scan_network", return_value=[device]
            ) as mock_arp,
            mock.patch("backend.app.services.enrichment.enrich_devices"),
            mock.patch("backend.app.scanner.classifier.scan_devices_ports") as mock_ports,
        ):
            result = _post(live_server, "/api/scan", {"target": "192.168.50.0/30", **payload})
        return result, mock_arp, mock_ports

    def test_options_reach_the_arp_sweep(self, live_server, tmp_path):
        (status, _), mock_arp, _ = self._scan(
            live_server, tmp_path, {"timeout": 2.5, "retries": 0, "gentle": True}
        )
        assert status == 200
        kwargs = mock_arp.call_args.kwargs
        assert (kwargs["timeout"], kwargs["retries"], kwargs["gentle"]) == (2.5, 0, True)

    def test_defaults_reach_the_arp_sweep(self, live_server, tmp_path):
        _, mock_arp, _ = self._scan(live_server, tmp_path, {})
        kwargs = mock_arp.call_args.kwargs
        assert (kwargs["timeout"], kwargs["retries"], kwargs["gentle"]) == (
            DEFAULT_TIMEOUT,
            DEFAULT_ARP_RETRIES,
            False,
        )

    def test_port_options_reach_the_port_scan(self, live_server, tmp_path):
        _, _, mock_ports = self._scan(
            live_server, tmp_path, {"scan_ports": True, "ports": "22,80", "snmp": True}
        )
        kwargs = mock_ports.call_args.kwargs
        assert kwargs["ports"] == [22, 80]
        assert kwargs["snmp"] is True
        assert callable(kwargs["progress_callback"])

    def test_port_scan_uses_defaults_when_no_port_options_are_given(self, live_server, tmp_path):
        _, _, mock_ports = self._scan(live_server, tmp_path, {"scan_ports": True})
        kwargs = mock_ports.call_args.kwargs
        assert "ports" not in kwargs
        assert "snmp" not in kwargs

    def test_no_port_scan_unless_asked(self, live_server, tmp_path):
        _, _, mock_ports = self._scan(live_server, tmp_path, {"ports": "22", "snmp": True})
        mock_ports.assert_not_called()

    def test_a_bad_option_is_reported_and_nothing_is_scanned(self, live_server, tmp_path):
        (status, payload), mock_arp, _ = self._scan(live_server, tmp_path, {"retries": 99})
        assert status == 500
        assert "retries must be between 0 and 5" in payload["message"]
        mock_arp.assert_not_called()

    def test_the_default_gateway_is_flagged(self, live_server, tmp_path):
        history_path = tmp_path / "scan_history.json"
        device = {"ip": "192.168.50.1", "mac": "aa:aa:aa:aa:aa:aa"}
        with (
            mock.patch("backend.app.config.HISTORY_FILE", str(history_path)),
            mock.patch("backend.app.scanner.arp_scanner.scan_network", return_value=[device]),
            mock.patch("backend.app.services.enrichment.enrich_devices"),
            mock.patch(
                "backend.app.services.network_utils.get_default_gateway",
                return_value="192.168.50.1",
            ) as mock_gateway,
        ):
            status, _ = _post(
                live_server, "/api/scan", {"target": "192.168.50.0/30", "iface": "eth9"}
            )

        assert status == 200
        mock_gateway.assert_called_once_with("eth9")
        saved = json.loads(history_path.read_text())
        assert saved["192.168.50.0/30 on eth9"]["devices"][0]["is_gateway"] is True


class TestDashboardPageEscaping:
    def test_interface_names_are_html_escaped(self, live_server):
        fake_iface = mock.Mock()
        fake_iface.name = 'eth0"><script>alert(1)</script>'
        fake_iface.ip = "192.168.1.5"

        with (
            mock.patch("scapy.all.get_working_ifaces", return_value=[fake_iface]),
            mock.patch("backend.app.server.handler._get_netmask", return_value=24),
        ):
            status, body = _request(live_server, "GET", "/")

        page = body.decode()
        assert status == 200
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_the_options_panel_is_present(self, live_server):
        with mock.patch("scapy.all.get_working_ifaces", return_value=[]):
            _, body = _request(live_server, "GET", "/")
        page = body.decode()
        for element_id in ("opt-ports", "opt-timeout", "opt-retries", "opt-snmp", "opt-gentle"):
            assert f'id="{element_id}"' in page
        assert "/api/status" in page


def test_threaded_server_serves_requests_concurrently(live_server):
    """Two requests whose handling overlaps in time: the first one's
    handler is held open until the second one has finished."""
    gate = threading.Event()
    finished_second = threading.Event()
    original = DashboardHandler._serve_history

    def held_history(self):
        gate.set()
        assert finished_second.wait(5), "the second request was blocked behind the first"
        original(self)

    with mock.patch.object(DashboardHandler, "_serve_history", held_history):
        results: dict = {}
        first = threading.Thread(
            target=lambda: results.setdefault(
                "first", _request(live_server, "GET", "/scan_history.json")
            ),
            daemon=True,
        )
        first.start()
        assert gate.wait(5)
        results["second"] = _request(live_server, "GET", "/api/status")
        finished_second.set()
        first.join(timeout=5)
        time.sleep(0)

    assert results["second"] == (200, {"scanning": False})
    assert "first" in results
