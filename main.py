#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
#
#        FILE:  main.py
#      AUTHOR:  Mai Tan Duc <ducmai.network@gmail.com>
#       USAGE:  sudo python3 main.py
#     CREATED:  2023-11-22
# DESCRIPTION:  A network scanner that can scan a local network
#               and identify the IP addresses and MAC addresses
#               of all connected devices.
#
# =============================================================================


# ------------------------------- Module Imports ------------------------------
# Import the necessary classes from the rich module
from rich.console import Console
from rich.theme import Theme

# Stdlib
import argparse
import dashboard
import asyncio
from typing import Any
import collections
import csv
import datetime
import ipaddress
import json
import os
import socket


# ------------------------------- Named Constant -------------------------------
DEFAULT_TIMEOUT = 1.0

# Where scan results are persisted, keyed by the exact network string
# that was scanned, so a later scan of the same network can report
# what changed. A module-level constant (rather than hardcoding the
# path in each function) so tests can point it at a scratch file
# instead of the real one, and the CLI's --history-file can override
# it.
HISTORY_FILE = 'scan_history.json'

# A small, fixed set of well-known ports probed by scan_device_ports()
# when port scanning is opted into - not a general-purpose port
# scanner, just enough to make a reasonable guess at a device's role.
COMMON_PORTS = [22, 80, 443, 3389, 9100]


# ---------------------------- Function Definitions ---------------------------
def validate_network(network: str) -> str:
    """Validate and normalise a user-supplied network address.

    Parameters
    ----------
    network : str
        The raw string typed by the user, e.g. "192.168.1.0/24".

    Returns
    -------
    str
        The input with surrounding whitespace removed.

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


# Define a function to scan a network
def scan_network(network: str | list[str], timeout: float = DEFAULT_TIMEOUT, iface: str | None = None) -> list[dict[str, Any]]:
    """Send an ARP broadcast to `network` and collect the replies.

    Parameters
    ----------
    network : str
        The network/address to scan, e.g. "192.168.1.0/24".
    timeout : float
        Seconds to wait for ARP replies.

        NOTE: this used to be hardcoded to 1 second regardless of the
        network's size - flagged in this project's own architecture
        review as a real gap: a /16 gets the same window as a /24 and
        will systematically under-report, since scapy.srp()'s timeout
        is a single wait covering the *entire* sweep, not a per-host
        retry budget. Exposing it lets a larger scan be given more
        time.

    Returns
    -------
    list[dict]
        One {"ip": ..., "mac": ...} dict per device that replied.
    """
    import scapy.all as scapy
    # Create an ARP request packet with the network address
    # ARP is used to map IP addresses to MAC addresses
    # pdst is the parameter for the destination IP address
    arp_request = scapy.ARP(pdst=network)  # type: ignore[attr-defined]
    # Create an Ethernet broadcast packet
    # Ethernet is a protocol for data transmission over a network
    # dst is the parameter for the destination MAC address
    # ff:ff:ff:ff:ff:ff is the MAC address for broadcasting to all devices
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # type: ignore[attr-defined]
    # Combine the ARP request and the Ethernet broadcast
    # This creates a packet asking all network devices for their MAC addresses
    arp_broadcast = broadcast / arp_request
    # Send and receive the packets and store the results
    # srp is a function from scapy that sends and receives packets at layer 2
    # timeout is the parameter for how long to wait for a response
    # verbose is the parameter for whether to print the details of the packets
    answered, unanswered = scapy.srp(
        arp_broadcast, timeout=timeout, verbose=False, iface=iface
    )
    # Create a list to store the IP and MAC addresses
    devices = []
    # Loop through the answered packets
    for packet in answered:
        # Extract the IP and MAC addresses from the packet
        # psrc is the parameter for the source IP address
        # hwsrc is the parameter for the source MAC address
        ip = packet[1].psrc
        mac = packet[1].hwsrc
        # Append them to the list as a dictionary
        # A dictionary is a data structure that stores key-value pairs
        devices.append({"ip": ip, "mac": mac})
    # Return the list of devices
    return devices



def is_mac_randomized(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def lookup_vendor(mac: str) -> str | None:
    """Look up the manufacturer that registered a MAC address's OUI
    (its first three octets), e.g. "b8:27:eb:11:22:33" ->
    "Raspberry Pi Foundation".

    Uses scapy's own bundled IEEE manufacturer database
    (`scapy.conf.manufdb`) - no extra dependency and no network lookup.

    Parameters
    ----------
    mac : str
        A MAC address, e.g. "9c:5a:6b:1e:4f:0c".

    Returns
    -------
    str or None
        The manufacturer name, or None if the OUI isn't in the
        database (very common for locally-administered/randomised
        MACs, which is expected, not an error).
    """
    import scapy.all as scapy
    vendor = scapy.conf.manufdb._get_manuf(mac)
    # _get_manuf() echoes the input back unchanged when there's no
    # match, rather than raising or returning None itself.
    if vendor.lower() == mac.lower():
        return None
    return vendor


async def _lookup_hostname_async(ip: str, timeout: float) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), flags=socket.NI_NAMEREQD),
            timeout=timeout
        )
        return host
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
    for d, h in zip(devices, hostnames):
        d["hostname"] = h


def enrich_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add "vendor" and "hostname" fields to each device dict in
    place, using lookup_vendor() and lookup_hostname().

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network().

    Returns
    -------
    list[dict]
        The same list, for convenient chaining - each dict has been
        mutated in place, not replaced.
    """
    for device in devices:
        device["vendor"] = lookup_vendor(device["mac"])
        device["is_randomized"] = is_mac_randomized(device["mac"])
    
    if devices:
        asyncio.run(_enrich_devices_async(devices))
    
    return devices


def find_ip_conflicts(devices: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Find any IP address that answered from more than one distinct
    MAC address in this scan.

    Two different MACs both claiming the same IP is the classic
    signature of either a misconfigured static IP, or an ARP-spoofing
    /man-in-the-middle attempt in progress.

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network().

    Returns
    -------
    dict[str, list[str]]
        Maps each conflicting IP to the sorted list of MAC addresses
        that answered for it. Empty if there are no conflicts.
    """
    macs_by_ip = collections.defaultdict(set)
    for device in devices:
        macs_by_ip[device["ip"]].add(device["mac"])

    return {
        ip: sorted(macs)
        for ip, macs in macs_by_ip.items()
        if len(macs) > 1
    }


def scan_device_ports(ip: str, ports: list[int] = COMMON_PORTS, timeout: float = 0.3) -> list[int]:
    """Attempt a TCP connect to each port in `ports` and return the
    ones that accepted a connection.

    A lightweight, best-effort probe of a small, fixed set of
    well-known ports - not a general-purpose port scanner. Each
    connection attempt is short and closed immediately, but with
    `len(ports)` attempts per device at up to `timeout` seconds each,
    this is still real added latency per device - which is exactly why
    it's opt-in (see scan_devices_ports()) rather than run by default.

    Parameters
    ----------
    ip : str
        The IP address to probe.
    ports : list[int]
        Which ports to try.
    timeout : float
        Seconds to wait for each connection attempt.

    Returns
    -------
    list[int]
        The subset of `ports` that accepted a connection, in the
        order they were probed.
    """
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


def classify_device(vendor: str | None, open_ports: list[int]) -> str:
    """A rough, best-effort guess at a device's role from its vendor
    name and open ports. Not authoritative - just a helpful label.

    Parameters
    ----------
    vendor : str or None
        As returned by lookup_vendor().
    open_ports : list[int]
        As returned by scan_device_ports().

    Returns
    -------
    str
        One of "printer", "router/switch", "windows host", "server",
        "web-enabled device", or "unknown".
    """
    vendor_lower = (vendor or "").lower()
    ports = set(open_ports or [])

    if 9100 in ports:  # raw/JetDirect printing
        return "printer"
    if any(keyword in vendor_lower for keyword in (
        "cisco", "netgear", "tp-link", "ubiquiti", "asustek", "d-link",
        "mikrotik", "juniper",
    )):
        return "router/switch"
    if 3389 in ports:  # RDP
        return "windows host"
    if 22 in ports:  # SSH
        return "server"
    if 80 in ports or 443 in ports:
        return "web-enabled device"
    return "unknown"


import concurrent.futures

def scan_devices_ports(
    devices: list[dict[str, Any]], 
    ports: list[int] = COMMON_PORTS, 
    timeout: float = 0.3,
    progress_callback: Any = None
) -> list[dict[str, Any]]:
    """Add "open_ports" and "role" fields to each device dict in
    place, using scan_device_ports() and classify_device(), utilizing threads for speed.
    """
    def _scan(device: dict[str, Any]) -> dict[str, Any]:
        open_ports = scan_device_ports(device["ip"], ports, timeout)
        device["open_ports"] = open_ports
        device["role"] = classify_device(device.get("vendor"), open_ports)
        return device

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_scan, d): d for d in devices}
        count = 0
        for future in concurrent.futures.as_completed(futures):
            device = future.result()
            count += 1
            if progress_callback:
                progress_callback(count, len(devices), device)
    return devices


def load_history(path: str) -> dict[str, Any]:
    """Load previously-persisted scan results, keyed by the exact
    network string that was scanned.

    Parameters
    ----------
    path : str
        Path to the history file.

    Returns
    -------
    dict[str, dict]
        Maps network -> {"timestamp": ISO 8601 str, "devices": [...]}.
        Empty if the file doesn't exist yet or isn't valid JSON -
        a missing/corrupt history file means "nothing to diff
        against", not an error worth crashing over.
    """
    try:
        with open(path) as f:
            import typing
            return typing.cast(dict[str, Any], json.load(f))
    except (OSError, json.JSONDecodeError):
        return {}


def save_scan(path: str, network: str, devices: list[dict[str, Any]], stats: dict[str, Any] | None = None) -> None:
    """Persist `devices` as the new most-recent scan for `network`,
    leaving any other network's entry in the history file untouched.

    Parameters
    ----------
    path : str
        Path to the history file.
    network : str
        The network that was scanned - the key this scan is stored
        under.
    devices : list[dict]
        The (ideally enriched) scan results to persist.
    """
    history = load_history(path)
    history[network] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "devices": devices,
    }
    if stats:
        history[network]["stats"] = stats
    with open(path, 'w') as f:
        json.dump(history, f, indent=2)


def diff_devices(previous_devices: list[dict[str, Any]], current_devices: list[dict[str, Any]]) -> dict[str, list]:
    """Compare two device lists by MAC address - a device's MAC is a
    far more stable identifier than its IP, which can easily change
    between scans under DHCP - and report what changed.

    Parameters
    ----------
    previous_devices : list[dict]
        Devices from an earlier scan (e.g. loaded via load_history()).
    current_devices : list[dict]
        Devices from the current scan.

    Returns
    -------
    dict
        "new": devices present now but not before.
        "missing": devices present before but not now.
        "ip_changed": (device, old_ip) pairs for devices whose MAC
        matches a previous scan but whose IP has changed.
    """
    previous_by_mac = {d["mac"]: d for d in previous_devices}
    current_by_mac = {d["mac"]: d for d in current_devices}

    new = [
        d for mac, d in current_by_mac.items() if mac not in previous_by_mac
    ]
    missing = [
        d for mac, d in previous_by_mac.items() if mac not in current_by_mac
    ]
    ip_changed = [
        (current_by_mac[mac], previous_by_mac[mac]["ip"])
        for mac in current_by_mac
        if mac in previous_by_mac
        and current_by_mac[mac]["ip"] != previous_by_mac[mac]["ip"]
    ]

    return {"new": new, "missing": missing, "ip_changed": ip_changed}


def export_devices(devices: list[dict[str, Any]], path: str, fmt: str | None = None) -> None:
    """Write `devices` to a CSV or JSON file.

    Parameters
    ----------
    devices : list[dict]
        Devices as returned by scan_network()/enrich_devices()
        /scan_devices_ports().
    path : str
        Where to write the file.
    fmt : str or None
        'csv' or 'json'. If None, inferred from `path`'s extension
        (.csv or .json).

    Raises
    ------
    ValueError
        If fmt is None and the extension isn't .csv or .json.
    OSError
        If the file can't be written.
    """
    if fmt is None:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            fmt = "csv"
        elif ext == ".json":
            fmt = "json"
        else:
            raise ValueError(
                f"cannot infer export format from {path!r} - pass "
                "fmt='csv'/'json' (or --format on the command line), "
                "or name the file .csv/.json"
            )

    if fmt == "csv":
        fieldnames = ["ip", "mac", "vendor", "hostname"]
        if any("role" in device for device in devices):
            fieldnames += ["open_ports", "role"]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            for device in devices:
                row = dict(device)
                if isinstance(row.get("open_ports"), list):
                    row["open_ports"] = ";".join(
                        str(port) for port in row["open_ports"]
                    )
                writer.writerow(row)
    else:  # json
        with open(path, "w") as f:
            json.dump(devices, f, indent=2)


# Define a function to print the results
def print_results(devices: list[dict[str, Any]]) -> None:
    if not devices:
        print('\nNo devices found.')
        return
    show_ports = any("role" in device for device in devices)
    headers = ["IP Address", "MAC Address", "Vendor", "Hostname"]
    if show_ports:
        headers += ["Open Ports", "Role"]
    print("\n" + "\t\t".join(headers), end="\n" + "-" * 70 + "\n")
    for device in devices:
        # Vendor/hostname are only present once enrich_devices() has
        # run; fall back to "-" so this still works for a plain,
        # un-enriched device list (e.g. in tests).
        vendor = device.get("vendor") or "-"
        hostname = device.get("hostname") or "-"
        mac_display = f"{device['mac']} (Random)" if device.get("is_randomized") else device["mac"]
        row = [device["ip"], mac_display, vendor, hostname]
        if show_ports:
            open_ports = device.get("open_ports") or []
            ports_str = (
                ",".join(str(port) for port in open_ports)
                if open_ports else "-"
            )
            row += [ports_str, device.get("role") or "-"]
        print("\t\t".join(row))


def print_conflicts(conflicts: dict[str, list[str]]) -> None:
    """Print a warning for each IP address that answered from more
    than one MAC address - see find_ip_conflicts()."""
    for ip, macs in conflicts.items():
        print_error(
            f"WARNING: {ip} responded from multiple MAC addresses "
            f"({', '.join(macs)}) - possible IP conflict or ARP "
            "spoofing."
        )


def print_diff(diff: dict[str, list]) -> None:
    """Print a summary of what changed since the last scan of this
    network - see diff_devices()."""
    if diff["new"]:
        print("\nNew devices since last scan:")
        for device in diff["new"]:
            print(f"  + {device['ip']}\t{device['mac']}")
    if diff["missing"]:
        print("\nDevices missing since last scan:")
        for device in diff["missing"]:
            print(f"  - {device['ip']}\t{device['mac']}")
    if diff["ip_changed"]:
        print("\nDevices with a changed IP since last scan:")
        for device, old_ip in diff["ip_changed"]:
            print(f"  ~ {device['mac']}\t{old_ip} -> {device['ip']}")


def print_error(message: str) -> None:
    """Print an error message in red using rich, via a shared console."""
    custom_theme = Theme({"danger": "red"})
    console = Console(theme=custom_theme)
    console.print(message, style="danger")


# --------------------------- Interactive Session ------------------------------
def run_interactive() -> int:
    """Run the interactive session (the original behaviour of this
    program), extended with the opt-in port scan, history diff, and
    export prompts added below.
    """
    # Ask the user to enter the network address
    network = input(
        "Enter the network address (e.g., 192.168.1.0 or 192.168.1.0/24): "
    )

    try:
        network = validate_network(network)
    except ValueError:
        print_error(
            f"{network} is not a valid network address. "
            "Please enter a valid IP address or network."
        )
        return 1

    try:
        devices = scan_network(network)
    except PermissionError:
        print_error(
            "Permission denied. This script needs to send raw packets - "
            "try running it with sudo/as root."
        )
        return 1
    except Exception as e:
        if type(e).__name__ == "Scapy_Exception" and "Permission" in str(e):
            print_error(
                "Permission denied. This script needs to send raw packets - "
                "try running it with sudo/as root."
            )
            return 1
        raise

    conflicts = find_ip_conflicts(devices)
    if conflicts:
        print_conflicts(conflicts)

    enrich_devices(devices)

    scan_ports_answer = input(
        "\nAlso probe common ports on each device and guess its role? "
        "This takes longer. [y/N]: "
    ).strip().lower()
    if scan_ports_answer in ("y", "yes"):
        scan_devices_ports(devices)

    print_results(devices)

    history = load_history(HISTORY_FILE)
    previous_entry = history.get(network)
    if previous_entry is not None:
        print_diff(diff_devices(previous_entry["devices"], devices))
    save_scan(HISTORY_FILE, network, devices)

    export_path = input(
        "\nExport results to a file (.csv or .json), or press Enter to "
        "skip: "
    ).strip()
    if export_path:
        try:
            export_devices(devices, export_path)
        except (OSError, ValueError) as e:
            print_error(f"Could not export results: {e}")
        else:
            print(f"Results exported to {export_path}.")

    return 0


# ------------------------------ Non-Interactive CLI ---------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a local network for devices via ARP, identifying "
                     "each one's IP and MAC address. Run with no arguments "
                     "for the interactive prompt.",
    )
    parser.add_argument(
        "--network",
        help="Network/address to scan, e.g. 192.168.1.0/24. Prompts "
             "interactively if omitted.",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Seconds to wait for ARP replies (default: "
             f"{DEFAULT_TIMEOUT}). A larger network may need more time "
             "to avoid under-reporting.",
    )
    parser.add_argument(
        "--output",
        help="Write results to this file. Format is inferred from the "
             "extension (.csv or .json) unless --format is given.",
    )
    parser.add_argument(
        "--format", choices=["csv", "json"],
        help="Force the export format instead of inferring it from "
             "--output's extension.",
    )
    parser.add_argument(
        "--scan-ports", action="store_true",
        help="Also probe a handful of common ports on each device and "
             "guess its role. Adds noticeable time per device, so this "
             "is opt-in.",
    )
    parser.add_argument(
        "--history-file", default=HISTORY_FILE,
        help=f"Where to persist scan history for diffing against future "
             f"scans (default: {HISTORY_FILE}).",
    )
    parser.add_argument(
        "--stream-jsonl", action="store_true",
        help="Output results as JSON lines to stdout (disables regular table printing).",
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Launch the web dashboard.",
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Port to run the dashboard on (default: 8080).",
    )
    parser.add_argument(
        "--no-history", action="store_true",
        help="Don't compare against or update scan history.",
    )
    return parser


def run_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Run one CLI-mode scan and return a process exit code."""
    try:
        network = validate_network(args.network)
    except ValueError:
        parser.error(f"{args.network!r} is not a valid network address")

    try:
        devices = scan_network(network, timeout=args.timeout)
    except PermissionError:
        print_error(
            "Permission denied. This script needs to send raw packets - "
            "try running it with sudo/as root."
        )
        return 1

    conflicts = find_ip_conflicts(devices)
    if conflicts:
        print_conflicts(conflicts)

    enrich_devices(devices)

    if args.scan_ports:
        scan_devices_ports(devices)

    if args.stream_jsonl:
        for device in devices:
            print(json.dumps(device))
    else:
        print_results(devices)

    if not args.no_history:
        history = load_history(args.history_file)
        previous_entry = history.get(network)
        if previous_entry is not None:
            print_diff(diff_devices(previous_entry["devices"], devices))
        save_scan(args.history_file, network, devices)

    if args.output:
        try:
            export_devices(devices, args.output, args.format)
        except (OSError, ValueError) as e:
            parser.error(f"could not export results: {e}")
        print(f"\nResults exported to {args.output}.")

    return 0


# ------------------------------- Main Function -------------------------------
def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.dashboard:
        dashboard.run_dashboard(port=args.port)
        return 0

    if args.network is None:
        return run_interactive()

    return run_cli(args, parser)


# --------------------------- Call the Main Function --------------------------
if __name__ == '__main__':
    raise SystemExit(main())
