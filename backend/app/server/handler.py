"""
==============================================================================
Module Name:   handler.py
Description:   Source module handler.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 handler.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Load dashboard HTML relative to this file (frontend/dashboard.html)
_FRONTEND_DIR = Path(__file__).resolve().parents[3] / "frontend"
_DASHBOARD_HTML_PATH = _FRONTEND_DIR / "dashboard.html"

import contextlib
import html
import logging
import re
import shutil
import socket
import struct
import subprocess  # nosec B404
from dataclasses import dataclass

from backend.app.config import DEFAULT_ARP_RETRIES, DEFAULT_TIMEOUT, MAX_ARP_RETRIES
from backend.app.scanner.classifier import parse_port_spec

logger = logging.getLogger(__name__)

# The dashboard only ever binds to loopback, so these are the only Host
# values a legitimate request carries. Anything else is either a mistake
# or a DNS-rebinding attempt: a hostile page pointing its own domain at
# 127.0.0.1 so the browser treats this server as same-origin for it.
_ALLOWED_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "[::1]"})

# Maximum number of addresses a single scan request may expand to (applies
# to both "start-end" ranges and plain CIDR input). Without a cap, a
# mistyped or malicious range (e.g. transposed octets) makes the server
# try to materialize a multi-million-entry list before a single ARP
# packet goes out - this bounds that to something a LAN sweep can
# actually finish in reasonable time.
MAX_RANGE_SIZE = 65536

# A scan request is a few hundred bytes of JSON. Anything near this size is a
# mistake or an attack, and is refused before it is read into memory.
MAX_BODY_BYTES = 64 * 1024


def _get_netmask(iface_name: str) -> int:
    """Best-effort lookup of an interface's IPv4 prefix length.

    Tries `ip -json addr show` first - iproute2 is the standard tool on
    current Linux distributions, and `ifconfig`/net-tools is no longer
    installed by default on several of them (Debian 11+, Ubuntu 20.04+).
    Falls back to parsing `ifconfig` output for macOS/BSD and older
    systems, and finally to a hardcoded /24 guess if neither tool is
    available or parsing fails.
    """
    ip_bin = shutil.which("ip")
    if ip_bin:
        try:
            out = subprocess.check_output(  # nosec B603
                [ip_bin, "-json", "addr", "show", iface_name]
            ).decode()
            for entry in json.loads(out):
                for addr_info in entry.get("addr_info", []):
                    if addr_info.get("family") == "inet" and "prefixlen" in addr_info:
                        return int(addr_info["prefixlen"])
        except Exception as err:
            logger.debug("`ip addr show` failed for %s: %s", iface_name, err)

    try:
        ifconfig_bin = shutil.which("ifconfig") or "/sbin/ifconfig"
        out = subprocess.check_output([ifconfig_bin, iface_name]).decode()  # nosec B603 B607
        match_hex = re.search(r"netmask\s+(0x[0-9a-fA-F]+)", out)
        if match_hex:
            return bin(int(match_hex.group(1), 16)).count("1")
        match_dec = re.search(
            r"(?:netmask|Mask:)\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out, re.IGNORECASE
        )
        if match_dec:
            mask_str = match_dec.group(1)
            mask_int = struct.unpack("!I", socket.inet_aton(mask_str))[0]
            return bin(mask_int).count("1")
    except Exception as err:
        logger.debug("ifconfig fallback failed for %s: %s", iface_name, err)
    return 24


with open(_DASHBOARD_HTML_PATH, encoding="utf-8") as _f:
    DASHBOARD_HTML = _f.read()


def _parse_target(target_input: str) -> tuple[list[str], str]:
    """Expand target string to a list of IPs and a display network string."""
    import ipaddress

    if "-" in target_input:
        start_ip, end_ip_str = target_input.split("-", 1)
        start_obj = ipaddress.IPv4Address(start_ip.strip())
        end_obj = ipaddress.IPv4Address(end_ip_str.strip())
        if start_obj > end_obj:
            start_obj, end_obj = end_obj, start_obj
        range_size = int(end_obj) - int(start_obj) + 1
        if range_size > MAX_RANGE_SIZE:
            raise ValueError(f"range too large ({range_size} addresses) - max is {MAX_RANGE_SIZE}")
        target_ips = [
            str(ipaddress.IPv4Address(ip)) for ip in range(int(start_obj), int(end_obj) + 1)
        ]
        network_str = f"{start_obj}-{end_obj}"
    else:
        net = ipaddress.ip_network(target_input, strict=False)
        if net.num_addresses > MAX_RANGE_SIZE:
            raise ValueError(
                f"network too large ({net.num_addresses} addresses) - max is {MAX_RANGE_SIZE}"
            )
        target_ips = [str(ip) for ip in net.hosts()]
        network_str = str(net)

    return target_ips, network_str


@dataclass(frozen=True)
class ScanOptions:
    """Validated scan settings from a POST /api/scan body."""

    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_ARP_RETRIES
    gentle: bool = False
    ports: list[int] | None = None
    snmp: bool = False


@dataclass(frozen=True)
class ScanRequest:
    """A validated POST /api/scan request."""

    target_ips: list[str]
    network_str: str
    iface: str | None
    scan_ports: bool
    options: ScanOptions


def _parse_options(data: dict[str, Any]) -> ScanOptions:
    """Validate the optional scan settings in a request body.

    Missing or empty values mean "use the default". `ports` and `snmp`
    only matter when `scan_ports` is on, so they are ignored otherwise.
    Raises ValueError with a message fit to show the user.
    """
    raw_timeout = data.get("timeout")
    timeout = DEFAULT_TIMEOUT
    if raw_timeout is not None and raw_timeout != "":
        try:
            timeout = float(raw_timeout)
        except (TypeError, ValueError):
            raise ValueError("timeout must be a number of seconds") from None
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")

    raw_retries = data.get("retries")
    retries = DEFAULT_ARP_RETRIES
    if raw_retries is not None and raw_retries != "":
        try:
            retries = int(raw_retries)
        except (TypeError, ValueError):
            raise ValueError("retries must be a whole number") from None
        if not 0 <= retries <= MAX_ARP_RETRIES:
            raise ValueError(f"retries must be between 0 and {MAX_ARP_RETRIES}")

    scan_ports = bool(data.get("scan_ports", False))
    ports = None
    spec = str(data.get("ports") or "").strip()
    if scan_ports and spec:
        try:
            ports = parse_port_spec(spec)
        except ValueError as e:
            raise ValueError(f"ports: {e}") from None

    return ScanOptions(
        timeout=timeout,
        retries=retries,
        gentle=bool(data.get("gentle", False)),
        ports=ports,
        snmp=scan_ports and bool(data.get("snmp", False)),
    )


class ScanState:
    """Single-slot scan lock plus a progress snapshot for GET /api/status.

    Only one scan may run at a time: they all use the same raw sockets
    and write the same history file. The server is threaded, so a scan
    in progress no longer blocks other requests - this is what lets the
    page poll for progress, and what turns a second click into a clear
    409 instead of a queue.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._info: dict[str, Any] = {}
        self._started = 0.0

    def try_begin(self) -> bool:
        if not self._lock.acquire(blocking=False):
            return False
        self._started = time.monotonic()
        self._info = {"phase": "starting", "ports_done": 0, "ports_total": 0}
        return True

    def set_phase(self, phase: str) -> None:
        self._info = {**self._info, "phase": phase}

    def progress(self, done: int, total: int, device: Any = None) -> None:
        """Port-scan progress. Shaped to be passed straight to
        scan_devices_ports() as its progress_callback, which also hands
        over the device it just finished."""
        self._info = {**self._info, "ports_done": done, "ports_total": total}

    def end(self) -> None:
        self._info = {}
        self._lock.release()

    def snapshot(self) -> dict[str, Any]:
        info = self._info
        if not info:
            return {"scanning": False}
        return {
            "scanning": True,
            "elapsed": round(time.monotonic() - self._started, 1),
            **info,
        }


SCAN_STATE = ScanState()


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Minimal HTTP handler: serves the dashboard UI and exposes two
    API endpoints — POST /api/scan and POST /api/clear.
    """

    # Per-connection socket timeout. Without it a client that promises a body
    # and never sends it (or just opens a socket and goes quiet) holds a
    # handler thread forever. Only reads are affected: a scan in progress is
    # not waiting on the client.
    timeout = 15

    def _json_response(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _forbid_unless_local(self) -> bool:
        """Reject requests that did not come from this dashboard's own page.

        POST /api/scan runs as whoever started the dashboard - usually
        root, for the raw sockets - and /api/clear deletes the history, so
        a page the user happens to have open in another tab must not be
        able to fire them (browsers send cross-site POSTs, and `text/plain`
        ones need no preflight). Browsers always attach Origin to a POST,
        so requiring it to match Host closes that hole; clients that send
        no Origin (curl, scripts) are not a browser attack and pass. The
        Host check closes DNS rebinding. Returns True (after replying 403)
        if the request was refused.
        """
        host = self.headers.get("Host", "")
        hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        origin = self.headers.get("Origin")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if (
            hostname.lower() not in _ALLOWED_HOSTNAMES
            or (origin is not None and urlsplit(origin).netloc != host)
            or fetch_site == "cross-site"
        ):
            self._json_response(403, {"status": "error", "message": "forbidden"})
            return True
        return False

    def do_POST(self) -> None:
        if self._forbid_unless_local():
            return
        if self.path == "/api/scan":
            self._handle_scan()
        elif self.path == "/api/clear":
            self._handle_clear()
        else:
            self.send_response(404)
            self.end_headers()

    def _read_body(self) -> bytes | None:
        """The request body, or None after replying with the error.

        Content-Length is checked before anything is read: it must be plain
        digits and no larger than MAX_BODY_BYTES. (`int()` alone accepts
        signs and underscores, `rfile.read(-1)` reads until the client closes
        the connection, and a huge value waits for data that never comes.)
        """
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        raw_length = raw_length.strip()
        if not (raw_length.isascii() and raw_length.isdigit()):
            self._json_response(400, {"status": "error", "message": "invalid Content-Length"})
            return None
        length = int(raw_length)
        if length > MAX_BODY_BYTES:
            self._json_response(
                413,
                {
                    "status": "error",
                    "message": f"request body too large (limit {MAX_BODY_BYTES} bytes)",
                },
            )
            return None
        try:
            return self.rfile.read(length)
        except OSError:  # includes the socket timeout set above
            self.close_connection = True
            # If the client is gone there is nobody to tell.
            with contextlib.suppress(OSError):
                self._json_response(408, {"status": "error", "message": "request body timed out"})
            return None

    @staticmethod
    def _parse_scan_request(post_data: bytes) -> ScanRequest:
        """Validate a POST /api/scan body. Raises ValueError, with a message
        fit to show the user, for anything the client got wrong."""
        import scapy.all as scapy  # type: ignore[import-untyped]

        try:
            data = json.loads(post_data.decode("utf-8"))
        except ValueError:  # bad JSON or bad UTF-8
            raise ValueError("request body is not valid JSON") from None
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")

        target_input = data.get("target") or ""
        iface = data.get("iface") or None
        if not isinstance(target_input, str) or (iface is not None and not isinstance(iface, str)):
            raise ValueError("target and iface must be strings")
        target_input = target_input.strip()
        options = _parse_options(data)

        if not target_input and iface:
            for ifc in scapy.get_working_ifaces():
                if ifc.name == iface and ifc.ip and ifc.ip != "127.0.0.1":
                    mask = _get_netmask(ifc.name)
                    target_input = f"{ifc.ip}/{mask}"
                    break
        if not target_input:
            raise ValueError("No target provided and no interface selected to infer subnet.")

        target_ips, network_str = _parse_target(target_input)
        if iface:
            network_str += f" on {iface}"
        return ScanRequest(
            target_ips=target_ips,
            network_str=network_str,
            iface=iface,
            scan_ports=bool(data.get("scan_ports", False)),
            options=options,
        )

    def _handle_scan(self) -> None:
        import scapy.all as scapy  # type: ignore[import-untyped]

        from backend.app.config import HISTORY_FILE
        from backend.app.scanner.arp_scanner import scan_network
        from backend.app.scanner.classifier import scan_devices_ports
        from backend.app.services.enrichment import enrich_devices
        from backend.app.services.history_service import save_scan
        from backend.app.services.network_utils import get_default_gateway

        post_data = self._read_body()
        if post_data is None:
            return

        # A JSON content type can't be sent cross-site without a CORS
        # preflight, which this server never approves - a second layer
        # beside the Origin check.
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self._json_response(
                415, {"status": "error", "message": "Content-Type must be application/json"}
            )
            return

        if not SCAN_STATE.try_begin():
            self._json_response(
                409, {"status": "error", "message": "A scan is already running - please wait."}
            )
            return

        try:
            # A bad request is the client's mistake (400); anything that fails
            # after this point is the server's (500).
            try:
                request = self._parse_scan_request(post_data)
            except ValueError as e:
                self._json_response(400, {"status": "error", "message": str(e)})
                return

            target_ips, network_str = request.target_ips, request.network_str
            iface, options = request.iface, request.options

            SCAN_STATE.set_phase("arp")
            devices = scan_network(
                target_ips,
                timeout=options.timeout,
                iface=iface,
                gentle=options.gentle,
                retries=options.retries,
            )

            # Count IPs that belong to a different interface (no ARP response expected)
            responded_ips = {d.get("ip") for d in devices}
            wrong_iface_count = 0
            for ip in target_ips:
                if ip in responded_ips:
                    continue
                route_res = scapy.conf.route.route(ip)[0]
                route_name = route_res.name if hasattr(route_res, "name") else str(route_res)
                if route_name != iface:
                    wrong_iface_count += 1

            responded = len(devices)
            no_response = max(0, len(target_ips) - responded - wrong_iface_count)

            stats: dict[str, Any] = {
                "responded": responded,
                "wrong_iface": wrong_iface_count,
                "no_response": no_response,
            }

            SCAN_STATE.set_phase("enrich")
            enrich_devices(devices)

            gw_ip = get_default_gateway(iface) if iface else None
            for d in devices:
                if gw_ip and d.get("ip") == gw_ip:
                    d["is_gateway"] = True

            if request.scan_ports:
                SCAN_STATE.set_phase("ports")
                port_kwargs: dict[str, Any] = {"progress_callback": SCAN_STATE.progress}
                if options.ports is not None:
                    port_kwargs["ports"] = options.ports
                if options.snmp:
                    port_kwargs["snmp"] = True
                scan_devices_ports(devices, **port_kwargs)

            SCAN_STATE.set_phase("saving")
            save_scan(HISTORY_FILE, network_str, devices, stats=stats)

            self._json_response(
                200,
                {"status": "success", "network": network_str, "found": len(devices)},
            )
        except Exception as e:
            self._json_response(500, {"status": "error", "message": str(e)})
        finally:
            SCAN_STATE.end()

    def _handle_clear(self) -> None:
        from backend.app.config import HISTORY_FILE

        try:
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
            self._json_response(200, {"status": "success"})
        except Exception as e:
            self._json_response(500, {"status": "error", "message": str(e)})

    def do_GET(self) -> None:
        if self._forbid_unless_local():
            return
        if self.path == "/":
            self._serve_dashboard()
        elif self.path == "/api/status":
            self._json_response(200, SCAN_STATE.snapshot())
        elif self.path.startswith("/scan_history.json"):
            self._serve_history()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_dashboard(self) -> None:
        import scapy.all as scapy  # type: ignore[import-untyped]

        ifaces = scapy.get_working_ifaces()
        valid_ifaces = []
        for iface in ifaces:
            # Exclude loopback interfaces
            if iface.name.startswith("lo"):
                continue
            if iface.ip and iface.ip != "127.0.0.1":
                valid_ifaces.append(iface)

        # Sort: eth/en over wlan/wl
        def iface_priority(ifc: Any) -> int:
            name = ifc.name.lower()
            if name.startswith(("en", "eth")):
                return 0
            if name.startswith(("wl", "wlan")):
                return 1
            return 2

        valid_ifaces.sort(key=iface_priority)

        iface_options = ""
        import ipaddress

        for i, iface in enumerate(valid_ifaces):
            selected = ' selected="selected"' if i == 0 else ""
            subnet_str = ""
            if iface.ip:
                mask = _get_netmask(iface.name)
                try:
                    net = ipaddress.ip_network(f"{iface.ip}/{mask}", strict=False)
                    subnet_str = str(net)
                except Exception:
                    subnet_str = f"{iface.ip}/{mask}"
            # Interface names/addresses come from the OS, but they still go
            # into markup - escape them like any other interpolated value.
            name = html.escape(str(iface.name), quote=True)
            subnet = html.escape(subnet_str, quote=True)
            addr = html.escape(str(iface.ip), quote=True)
            iface_options += (
                f'<option value="{name}" data-subnet="{subnet}"{selected}>{name} ({addr})</option>'
            )

        page = DASHBOARD_HTML.replace("<!-- IFACE_OPTIONS -->", iface_options)
        body = page.encode("utf-8")
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

    def log_message(self, format: str, *args: Any) -> None:
        # Silence default per-request logging to keep the console clean
        pass


class ReuseTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded, so a scan in progress doesn't stop the page, the history
    file or GET /api/status from being served. Request threads are daemons:
    Ctrl-C shouldn't wait on a scan that is still running."""

    allow_reuse_address = True
    daemon_threads = True
