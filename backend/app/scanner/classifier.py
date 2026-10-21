"""
==============================================================================
Module Name:   classifier.py
Description:   Source module classifier.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 classifier.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import concurrent.futures
import re
import secrets
import socket
from typing import Any

from backend.app.config import COMMON_PORTS, MAX_SCAN_WORKERS, PORT_PRESETS, SNMP_PORT

# Source-port range for the SYN scan's batch: the unprivileged ephemeral
# range, so replies can't be mistaken for traffic to a well-known port.
_SYN_SOURCE_PORT_MIN = 40000
_SYN_SOURCE_PORT_SPAN = 20000


def _parse_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise ValueError(f"{text.strip()!r} is not a valid port number") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def parse_port_spec(spec: str) -> list[int]:
    """Turn a user-supplied port selection into a list of ports.

    Accepts a preset name from `config.PORT_PRESETS` ("quick", "common"),
    or a comma-separated list of ports and inclusive ranges such as
    "22,80,8000-8010". Duplicates are dropped; the order given is the
    order the ports are probed in.

    Raises
    ------
    ValueError
        On an empty entry, a non-numeric or out-of-range port, or a
        range whose start is greater than its end.
    """
    spec = spec.strip()
    if spec.lower() in PORT_PRESETS:
        return list(PORT_PRESETS[spec.lower()])

    ports: list[int] = []
    seen: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty entry in port list")
        if "-" in part:
            start_text, _, end_text = part.partition("-")
            start, end = _parse_port(start_text), _parse_port(end_text)
            if start > end:
                raise ValueError(f"invalid port range {part!r}: start is greater than end")
            candidates: list[int] = list(range(start, end + 1))
        else:
            candidates = [_parse_port(part)]
        for port in candidates:
            if port not in seen:
                seen.add(port)
                ports.append(port)
    return ports


def _ber(tag: int, payload: bytes) -> bytes:
    """One BER TLV. Every field in the SNMP probe below is far under 128
    bytes, so only the short length form is needed."""
    return bytes([tag, len(payload)]) + payload


def _snmp_get_request(request_id: int, community: bytes) -> bytes:
    """An SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""
    sys_descr_oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = _ber(0x30, _ber(0x06, sys_descr_oid) + _ber(0x05, b""))
    pdu = _ber(
        0xA0,
        _ber(0x02, request_id.to_bytes(4, "big"))
        + _ber(0x02, b"\x00")  # error-status
        + _ber(0x02, b"\x00")  # error-index
        + _ber(0x30, varbind),
    )
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community) + pdu)  # version 1 = v2c


def snmp_probe(
    ip: str,
    timeout: float = 0.3,
    port: int = SNMP_PORT,
    community: bytes = b"public",
) -> bool:
    """True if an SNMP agent on `ip` answers an SNMPv2c GET for sysDescr.0.

    SNMP is UDP, so the TCP probes in `scan_device_ports` can never see
    it. An agent only replies when the community string matches, so this
    detects agents that accept `community` (default "public") - a False
    result does not prove SNMP is off, only that it isn't answering to
    that community. An ICMP port-unreachable or a timeout both count as
    "no agent".
    """
    request_id = 0x01000000 + secrets.randbelow(0x7E000000)  # always 4 bytes, sign bit clear
    packet = _snmp_get_request(request_id, community)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.send(packet)
            reply = sock.recv(1500)
        except OSError:
            return False
    return reply[:1] == b"\x30" and request_id.to_bytes(4, "big") in reply


def _tcp_syn_scan(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Half-open (SYN) scan: send a bare SYN to every port in one batch,
    record each SYN+ACK as open, then tear those attempts down ourselves
    with a RST before a full handshake ever completes - the same technique
    nmap's default privileged scan (`-sS`) uses. Lower overhead per port
    than `scan_device_ports`'s TCP-connect probe, and the target's own
    application never sees an established connection (so e.g. an HTTP
    or SSH access log never gets a line for it).

    All the SYNs go out in a single `sr()` call, so `timeout` is one wait
    for the whole port list rather than one per port - a host that
    silently drops packets costs `timeout`, not `len(ports) * timeout`.
    One source port is used for the whole batch; replies are told apart
    by the port they came from.

    Needs raw-socket privileges, same as the ARP sweep this tool
    already requires - no new privilege footprint for callers that
    already run the scanner as intended.
    """
    import scapy.all as scapy  # type: ignore[import-untyped]

    if not ports:
        return []

    sport = _SYN_SOURCE_PORT_MIN + secrets.randbelow(_SYN_SOURCE_PORT_SPAN)
    syns = scapy.IP(dst=ip) / scapy.TCP(sport=sport, dport=list(ports), flags="S")  # type: ignore[attr-defined]
    answered, _unanswered = scapy.sr(syns, timeout=timeout, verbose=False)

    open_set: set[int] = set()
    resets = []
    for sent, received in answered:
        if not received.haslayer(scapy.TCP):  # type: ignore[attr-defined]
            continue
        tcp_layer = received.getlayer(scapy.TCP)  # type: ignore[attr-defined]
        # SYN+ACK only - anything else (RST, RST+ACK, ...) isn't "open"
        if tcp_layer is None or tcp_layer.flags != 0x12:
            continue
        port = sent[scapy.TCP].dport  # type: ignore[attr-defined]
        open_set.add(port)
        resets.append(
            scapy.IP(dst=ip)  # type: ignore[attr-defined]
            / scapy.TCP(sport=sport, dport=port, flags="R", seq=tcp_layer.ack)  # type: ignore[attr-defined]
        )
    if resets:
        scapy.send(resets, verbose=False)
    return [port for port in ports if port in open_set]  # keep the order given


def _tcp_connect_scan(ip: str, ports: list[int], timeout: float) -> list[int]:
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except OSError:
                pass
    return open_ports


def scan_device_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 0.3,
    method: str = "connect",
    *,
    snmp: bool = False,
) -> list[int]:
    """Probe each port in `ports` and return the ones found open.

    Parameters
    ----------
    ip : str
        The IP address to probe.
    ports : list[int] or None
        Which ports to try. Defaults to COMMON_PORTS.
    timeout : float
        Seconds to wait for each probe.
    method : str
        "connect" (default) completes a full TCP handshake per port -
        no special privileges needed beyond a normal socket. "syn"
        does a half-open SYN probe instead (see `_tcp_syn_scan`) -
        needs the same raw-socket privileges as the ARP sweep.
    snmp : bool
        Also send a UDP SNMP GET (see `snmp_probe`). If an agent
        answers, 161 is appended to the result - note that, unlike the
        other ports, 161 means UDP.

    Returns
    -------
    list[int]
        The subset of `ports` that accepted a connection, in the
        order they were probed, then 161 if `snmp` found an agent.
    """
    ports = COMMON_PORTS if ports is None else ports

    if method == "syn":
        open_ports = _tcp_syn_scan(ip, ports, timeout)
    else:
        open_ports = _tcp_connect_scan(ip, ports, timeout)

    if snmp and SNMP_PORT not in open_ports and snmp_probe(ip, timeout):
        open_ports.append(SNMP_PORT)
    return open_ports


# Hostname hints. A device's own name is often a stronger clue than a
# single open port, but names are free text, so a hint is worth less than
# a strong port signature (+5): it can settle a tie or a weak guess, never
# override a camera/printer port. Matched against the hostname's
# alphanumeric tokens ("ap-lobby" -> "ap", "lobby") or, for default names
# that fuse a prefix to a serial number, against token prefixes.
_HOSTNAME_HINT_POINTS = 3

_HOSTNAME_TOKEN_HINTS: dict[str, frozenset[str]] = {
    "ip camera": frozenset(
        {"cam", "ipcam", "camera", "nvr", "dvr", "hikvision", "dahua", "reolink", "annke"}
    ),
    "printer": frozenset(
        {"printer", "laserjet", "officejet", "deskjet", "mfc", "pixma", "lexmark", "kyocera"}
    ),
    "access point": frozenset({"ap", "uap", "unifi", "wap"}),
    "router/switch": frozenset(
        {"sw", "switch", "rtr", "router", "gw", "gateway", "fw", "firewall"}
    ),
    "smart home device": frozenset(
        {"esp", "esp32", "esp8266", "tasmota", "shelly", "sonoff", "tuya", "homeassistant"}
    ),
    "linux host": frozenset({"raspberrypi", "ubuntu", "debian"}),
    "server": frozenset({"nas", "proxmox", "pve", "synology", "truenas", "docker", "k8s"}),
}

# (prefix, role) for factory-default names like DESKTOP-AB12CD3 or BRN30055C1234,
# where the model number or serial is fused to the prefix.
_HOSTNAME_PREFIX_HINTS: tuple[tuple[str, str], ...] = (
    ("desktop-", "windows host"),
    ("laptop-", "windows host"),
    ("win-", "windows host"),
    ("brn", "printer"),  # Brother default
    ("npi", "printer"),  # HP default
    ("shelly", "smart home device"),  # shelly1-AABBCC, shellyplug-s-AABBCC, ...
)

_ROUTER_NAME = re.compile(r"r\d+")  # R1, R2 ... in lab/NOC naming


def _hostname_hints(hostname: str | None) -> set[str]:
    """The roles a hostname hints at (empty if it says nothing)."""
    if not hostname:
        return set()
    name = hostname.strip().lower().split(".")[0]  # drop the domain part
    tokens = [t for t in re.split(r"[^a-z0-9]+", name) if t]
    roles = {
        role for role, words in _HOSTNAME_TOKEN_HINTS.items() if any(t in words for t in tokens)
    }
    roles.update(role for prefix, role in _HOSTNAME_PREFIX_HINTS if name.startswith(prefix))
    if any(_ROUTER_NAME.fullmatch(t) for t in tokens):
        roles.add("router/switch")
    return roles


def classify_device_scored(
    vendor: str | None, open_ports: list[int], hostname: str | None = None
) -> tuple[str, int]:
    """Like classify_device(), but also returns how strongly the winning
    role was supported.

    The score is the winning role's raw points: 5 or more is a strong
    signature (e.g. a camera or printer port), 3-4 a solid combination,
    1-2 a weak hint. A role of "unknown" - no evidence, or a tie - has
    score 0.
    """
    vendor_lower = (vendor or "").lower()
    ports = set(open_ports or [])

    scores: dict[str, int] = {
        "router/switch": 0,
        "access point": 0,
        "ip camera": 0,
        "smart home device": 0,
        "printer": 0,
        "windows host": 0,
        "linux host": 0,
        "server": 0,
        "web-enabled device": 0,
    }

    # Narrow, high-confidence Layer 4 signatures
    if 554 in ports or {8000, 37777, 34567} & ports:
        scores["ip camera"] += 5
    if {1883, 8883} & ports:
        scores["smart home device"] += 3
    if {9100, 515, 631} & ports:
        scores["printer"] += 5

    # Windows
    windows_hits = {135, 445, 3389} & ports
    if len(windows_hits) >= 2:
        scores["windows host"] += 4
    elif 3389 in windows_hits:
        scores["windows host"] += 3

    # Server
    server_ports = {3306, 5432, 21, 22, 25, 143}
    server_hits = server_ports & ports
    if len(server_hits) >= 2:
        scores["server"] += 4

    # SSH alone: weak, generic signal
    if 22 in ports and len(server_hits) < 2:
        scores["server"] += 1
        scores["linux host"] += 1

    # Catch-all web
    if {80, 443, 8080, 8443} & ports:
        scores["web-enabled device"] += 1

    # Vendor-based signals
    networking_vendors = ("cisco", "juniper", "mikrotik", "netgear", "tp-link", "asustek", "d-link")
    if any(keyword in vendor_lower for keyword in networking_vendors):
        if 23 in ports or 161 in ports:
            scores["router/switch"] += 5
        else:
            scores["router/switch"] += 2

    camera_vendors = ("hikvision", "dahua")
    if any(keyword in vendor_lower for keyword in camera_vendors):
        if {554, 8000, 37777, 34567} & ports:
            scores["ip camera"] += 5
        else:
            scores["ip camera"] += 2

    iot_vendors = ("espressif", "xiaomi", "lumi", "tuya", "sonoff")
    if any(keyword in vendor_lower for keyword in iot_vendors):
        scores["smart home device"] += 3

    ap_vendors = ("ubiquiti", "aruba")
    if any(keyword in vendor_lower for keyword in ap_vendors):
        if 23 not in ports:
            scores["access point"] += 4
        else:
            scores["router/switch"] += 2

    for role in _hostname_hints(hostname):
        scores[role] += _HOSTNAME_HINT_POINTS

    best_category = max(scores, key=scores.__getitem__)
    best_score = scores[best_category]

    if best_score == 0:
        return "unknown", 0

    # Guard against ties
    top_categories = [c for c, s in scores.items() if s == best_score]
    if len(top_categories) > 1:
        return "unknown", 0

    return best_category, best_score


def classify_device(vendor: str | None, open_ports: list[int], hostname: str | None = None) -> str:
    """A rough, best-effort guess at a device's role from its vendor
    name, open ports and (optionally) hostname.

    Parameters
    ----------
    vendor : str or None
        As returned by lookup_vendor().
    open_ports : list[int]
        As returned by scan_device_ports().
    hostname : str or None
        As set by enrich_devices(). A name like "ESP_1A2B3C" or
        "DESKTOP-AB12CD3" settles ties and weak guesses, but never
        outweighs a strong port signature. Omitting it gives the same
        result as before hostnames were considered.

    Returns
    -------
    str
        One of the categorized roles or "unknown".
    """
    return classify_device_scored(vendor, open_ports, hostname)[0]


def scan_devices_ports(
    devices: list[dict[str, Any]],
    ports: list[int] | None = None,
    timeout: float = 0.3,
    progress_callback: Any = None,
    method: str = "connect",
    max_workers: int | None = None,
    snmp: bool = False,
) -> list[dict[str, Any]]:
    """Add "open_ports" and "role" fields to each device dict in
    place, using scan_device_ports() and classify_device(), utilizing
    threads for speed.

    `method` and `snmp` are passed straight through to
    scan_device_ports() - see there for what each does.

    `max_workers` caps how many devices are scanned in parallel
    (default `config.MAX_SCAN_WORKERS`). Ports are probed one at a time
    per device, so it is also the most sockets this scan holds open.
    """
    ports = COMMON_PORTS if ports is None else ports
    workers = max(1, min(max_workers or MAX_SCAN_WORKERS, len(devices)))

    def _scan(device: dict[str, Any]) -> dict[str, Any]:
        open_ports = scan_device_ports(device["ip"], ports, timeout, method=method, snmp=snmp)
        device["open_ports"] = open_ports
        device["role"] = classify_device(device.get("vendor"), open_ports, device.get("hostname"))
        return device

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_scan, d): d for d in devices}
        for count, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            device = future.result()
            if progress_callback:
                progress_callback(count, len(devices), device)
    return devices
