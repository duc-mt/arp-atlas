"""HTTP request handler for the ARP Atlas web dashboard."""

from __future__ import annotations

import json
import os
import socketserver
import http.server
from pathlib import Path
from typing import Any

# Load dashboard HTML relative to this file (frontend/dashboard.html)
_FRONTEND_DIR = Path(__file__).resolve().parents[4] / "frontend"
_DASHBOARD_HTML_PATH = _FRONTEND_DIR / "dashboard.html"

with open(_DASHBOARD_HTML_PATH, encoding="utf-8") as _f:
    DASHBOARD_HTML = _f.read()


def _parse_target(target_input: str) -> tuple[list[str], str]:
    """Expand target string to a list of IPs and a display network string."""
    import ipaddress

    if "-" in target_input:
        start_ip, end_ip = target_input.split("-", 1)
        start_obj = ipaddress.IPv4Address(start_ip.strip())
        end_obj = ipaddress.IPv4Address(end_ip.strip())
        if start_obj > end_obj:
            start_obj, end_obj = end_obj, start_obj
        target_ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_obj), int(end_obj) + 1)]
        network_str = f"{start_obj}-{end_obj}"
    else:
        net = ipaddress.ip_network(target_input, strict=False)
        target_ips = [str(ip) for ip in net.hosts()]
        network_str = str(net)

    return target_ips, network_str


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Minimal HTTP handler: serves the dashboard UI and exposes two
    API endpoints — POST /api/scan and POST /api/clear.
    """

    def _json_response(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/scan":
            self._handle_scan()
        elif self.path == "/api/clear":
            self._handle_clear()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_scan(self) -> None:
        import scapy.all as scapy  # type: ignore[import-untyped]

        from backend.app.scanner.arp_scanner import scan_network
        from backend.app.services.enrichment import enrich_devices
        from backend.app.scanner.classifier import scan_devices_ports
        from backend.app.services.history_service import save_scan
        from backend.app.config import HISTORY_FILE

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data.decode("utf-8"))
            target_input = data.get("target", "").strip()
            iface = data.get("iface")
            scan_ports = data.get("scan_ports", False)

            target_ips, network_str = _parse_target(target_input)
            if iface:
                network_str += f" on {iface}"

            devices = scan_network(target_ips, iface=iface)

            # Count IPs that belong to a different interface (no ARP response expected)
            responded_ips = {d.get("ip") for d in devices}
            wrong_iface_count = 0
            for ip in target_ips:
                if ip in responded_ips:
                    continue
                route = scapy.conf.route.route(ip)[0]
                if hasattr(route, "name"):
                    route = route.name
                if route != iface:
                    wrong_iface_count += 1

            responded = len(devices)
            no_response = max(0, len(target_ips) - responded - wrong_iface_count)

            stats: dict[str, Any] = {
                "responded": responded,
                "wrong_iface": wrong_iface_count,
                "no_response": no_response,
            }

            enrich_devices(devices)
            if scan_ports:
                scan_devices_ports(devices)

            save_scan(HISTORY_FILE, network_str, devices, stats=stats)

            self._json_response(
                200,
                {"status": "success", "network": network_str, "found": len(devices)},
            )
        except Exception as e:
            self._json_response(500, {"status": "error", "message": str(e)})

    def _handle_clear(self) -> None:
        from backend.app.config import HISTORY_FILE

        try:
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
            self._json_response(200, {"status": "success"})
        except Exception as e:
            self._json_response(500, {"status": "error", "message": str(e)})

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._serve_dashboard()
        elif self.path.startswith("/scan_history.json"):
            self._serve_history()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_dashboard(self) -> None:
        import scapy.all as scapy  # type: ignore[import-untyped]

        ifaces = scapy.get_working_ifaces()
        iface_options = ""
        for iface in ifaces:
            if iface.ip:
                iface_options += f'<option value="{iface.name}">{iface.name} ({iface.ip})</option>'

        html = DASHBOARD_HTML.replace("<!-- IFACE_OPTIONS -->", iface_options)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def _serve_history(self) -> None:
        from backend.app.config import HISTORY_FILE

        if os.path.exists(HISTORY_FILE):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            with open(HISTORY_FILE, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence default per-request logging to keep the console clean
        pass


class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
