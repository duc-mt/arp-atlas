"""
==============================================================================
Module Name:   main.py
Description:   Source module main.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.0.0
License:       MIT
==============================================================================
Usage:         python3 main.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
from typing import Any

from backend.app.config import (
    DEFAULT_ARP_RETRIES,
    DEFAULT_TIMEOUT,
    HISTORY_FILE,
    MAX_ARP_RETRIES,
    MIN_WATCH_INTERVAL,
)
from backend.app.scanner.arp_scanner import scan_network, validate_network
from backend.app.scanner.classifier import parse_port_spec, scan_devices_ports
from backend.app.scanner.port_scanner_async import scan_devices_ports_async
from backend.app.services.conflict_service import find_ip_conflicts
from backend.app.services.enrichment import enrich_devices
from backend.app.services.export_service import export_devices
from backend.app.services.history_service import (
    diff_devices,
    known_device_macs,
    load_history,
    save_scan,
)
from backend.app.services.network_utils import get_default_gateway, is_permission_error
from backend.app.services.watch_service import detect_changes
from cli.arp_atlas_cli.formatters import (
    print_alerts,
    print_conflicts,
    print_diff,
    print_error,
    print_results,
)


def _is_permission_error(exc: Exception) -> bool:
    """True for a raw PermissionError, or for scapy's own
    Scapy_Exception when it's wrapping a permission failure - which is
    what scapy.srp() raises on some platforms instead of a plain
    PermissionError when raw-socket access is denied.
    """
    return is_permission_error(exc)


def _scan_or_none(network: str, **kwargs: Any) -> list[dict[str, Any]] | None:
    """Run scan_network(), printing a friendly message and returning
    None on a permission failure instead of letting a raw traceback
    escape - shared by both the interactive and non-interactive paths
    so a fix to one can't silently miss the other.
    """
    try:
        return scan_network(network, **kwargs)
    except Exception as e:
        if _is_permission_error(e):
            print_error(
                "Permission denied. This script needs to send raw packets - "
                "try running it with sudo/as root."
            )
            return None
        raise


def check_npcap_on_windows() -> None:
    """On Windows, abort early if Npcap is not installed."""
    if sys.platform == "win32":
        system32 = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32")
        paths = [
            os.path.join(system32, "Npcap", "wpcap.dll"),
            os.path.join(system32, "wpcap.dll"),
        ]
        if not any(os.path.exists(p) for p in paths):
            print("\n[!] ERROR: Npcap is not installed.", file=sys.stderr)
            print(
                "[!] Arp-Atlas uses Scapy, which requires Npcap to capture and send packets on Windows.",
                file=sys.stderr,
            )
            print(
                "[!] Please download and install Npcap from: https://npcap.com/#download",
                file=sys.stderr,
            )
            print(
                "[!] (Make sure to check 'Install Npcap in WinPcap API-compatible Mode' if prompted during installation)\n",
                file=sys.stderr,
            )
            sys.exit(1)


def check_privileges() -> None:
    """Ensure process has required privileges to send raw packets before launching."""
    if sys.platform == "win32":
        return

    if os.geteuid() == 0:
        return

    # Check if raw socket capability or BPF read/write permission is present
    has_raw_access = False
    try:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        has_raw_access = True
    except (PermissionError, OSError):
        has_raw_access = False

    if not has_raw_access:
        print("\n[!] ERROR: Insufficient privileges to send raw network packets.", file=sys.stderr)
        print(
            "[!] ARP Atlas requires root privileges (or configured capabilities/bpf access).",
            file=sys.stderr,
        )
        print("[!] Please re-run with sudo:\n", file=sys.stderr)
        cmd_args = " ".join(sys.argv)
        print(f"    sudo {cmd_args}\n", file=sys.stderr)
        sys.exit(1)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a local network for devices via ARP, identifying "
        "each one's IP and MAC address. Run with no arguments "
        "for the interactive prompt.",
    )
    parser.add_argument(
        "--network",
        help="Network/address to scan, e.g. 192.168.1.0/24. Prompts interactively if omitted.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Seconds to wait for ARP replies (default: {DEFAULT_TIMEOUT}). "
        "A larger network may need more time to avoid under-reporting.",
    )
    parser.add_argument(
        "--output",
        help="Write results to this file. Format is inferred from the extension (.csv or .json) "
        "unless --format is given.",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        help="Force the export format instead of inferring it from --output's extension.",
    )
    parser.add_argument(
        "--scan-ports",
        action="store_true",
        help="Also probe common TCP ports on each device (see --ports) and guess its role. "
        "Adds noticeable time per device, so this is opt-in.",
    )
    parser.add_argument(
        "--ports",
        metavar="SPEC",
        help="With --scan-ports, which TCP ports to probe: a preset ('common' - the default, "
        "every port the role classifier looks at - or 'quick', the original five) or a "
        "comma-separated list with ranges, e.g. 22,80,8000-8010.",
    )
    parser.add_argument(
        "--snmp-probe",
        action="store_true",
        help="With --scan-ports, also send an SNMPv2c GET (community 'public') to UDP/161 on "
        "each device; an agent that answers shows up as port 161 in open_ports. SNMP is UDP, "
        "so the TCP probes can never find it. Agents using another community stay silent.",
    )
    parser.add_argument(
        "--async-scan",
        action="store_true",
        help="With --scan-ports, probe ports with the asyncio scanner (a hard cap on "
        "concurrently open sockets) instead of the thread pool. TCP connect only - "
        "can't be combined with --syn-scan.",
    )
    parser.add_argument(
        "--syn-scan",
        action="store_true",
        help="With --scan-ports, use a half-open TCP SYN probe per port instead of a "
        "full connect() - lower overhead, and the target's own application-layer "
        "logging never sees a connection since the handshake is torn down before "
        "it completes. Needs the same raw-socket privileges as the ARP sweep.",
    )
    parser.add_argument(
        "--gentle-scan",
        action="store_true",
        help="Pace the ARP sweep: one host at a time, in randomized order, with a "
        "small random delay between each, instead of one broadcast burst. "
        "Friendlier to switches/monitoring tuned to flag a broadcast burst or a "
        "sequential sweep; takes much longer on large ranges.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        metavar="N",
        help=f"How many times the normal ARP sweep re-sends requests that got no reply "
        f"(default: {DEFAULT_ARP_RETRIES}, max {MAX_ARP_RETRIES}). Raises the chance of "
        "finding devices on busy Wi-Fi or ones that are asleep, at the cost of one more "
        "--timeout wait per retry. 0 sends each request once. Ignored by --gentle-scan.",
    )
    parser.add_argument(
        "--watch",
        type=float,
        metavar="SECONDS",
        help=f"Re-scan every SECONDS (minimum {MIN_WATCH_INTERVAL:g}) until Ctrl-C and alert "
        "on a device never seen before on this network, or an address answering from a "
        "different MAC than last time - the gateway's MAC changing is the classic ARP "
        "spoofing sign. The first scan only records a baseline. Needs scan history.",
    )
    parser.add_argument(
        "--history-file",
        default=HISTORY_FILE,
        help=f"Where to persist scan history for diffing against future scans "
        f"(default: {HISTORY_FILE}).",
    )
    parser.add_argument(
        "--stream-jsonl",
        action="store_true",
        help="Output results as JSON lines to stdout (disables regular table printing).",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the web dashboard.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to run the dashboard on (default: 8080).",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Don't compare against or update scan history.",
    )
    return parser


def run_interactive() -> int:
    """Run the interactive session — prompts for network, then scans."""
    network = input("Enter the network address (e.g., 192.168.1.0 or 192.168.1.0/24): ")

    try:
        network = validate_network(network)
    except ValueError:
        print_error(
            f"{network} is not a valid network address. Please enter a valid IP address or network."
        )
        return 1

    devices = _scan_or_none(network)
    if devices is None:
        return 1

    conflicts = find_ip_conflicts(devices)
    if conflicts:
        print_conflicts(conflicts)

    enrich_devices(devices)

    scan_ports_answer = (
        input(
            "\nAlso probe common ports on each device and guess its role? "
            "This takes longer. [y/N]: "
        )
        .strip()
        .lower()
    )
    if scan_ports_answer in ("y", "yes"):
        scan_devices_ports(devices)

    print_results(devices)

    history = load_history(HISTORY_FILE)
    previous_entry = history.get(network)
    if previous_entry is not None:
        print_diff(diff_devices(previous_entry["devices"], devices))
    save_scan(HISTORY_FILE, network, devices)

    export_path = input(
        "\nExport results to a file (.csv or .json), or press Enter to skip: "
    ).strip()
    if export_path:
        try:
            export_devices(devices, export_path)
        except (OSError, ValueError) as e:
            print_error(f"Could not export results: {e}")
        else:
            print(f"Results exported to {export_path}.")

    return 0


def _port_scan_options(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Validate the port-scan flags and return the extra keyword arguments
    for the scanner. Runs before the ARP sweep so a typo in --ports fails
    immediately instead of after the whole network has been scanned."""
    used = {
        "--ports": args.ports is not None,
        "--snmp-probe": args.snmp_probe,
        "--async-scan": args.async_scan,
    }
    for flag, is_used in used.items():
        if is_used and not args.scan_ports:
            parser.error(f"{flag} requires --scan-ports")
    if args.async_scan and args.syn_scan:
        parser.error(
            "--async-scan only does TCP connect scans; it can't be combined with --syn-scan"
        )

    options: dict[str, Any] = {}
    if args.ports is not None:
        try:
            options["ports"] = parse_port_spec(args.ports)
        except ValueError as e:
            parser.error(f"--ports: {e}")
    if args.snmp_probe:
        options["snmp"] = True
    return options


def _arp_scan_kwargs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, Any]:
    """The keyword arguments for scan_network(), validated up front.
    `retries` is only passed when given, so scan_network()'s own default
    applies otherwise."""
    kwargs: dict[str, Any] = {"timeout": args.timeout, "gentle": args.gentle_scan}
    if args.retries is not None:
        if not 0 <= args.retries <= MAX_ARP_RETRIES:
            parser.error(f"--retries must be between 0 and {MAX_ARP_RETRIES}")
        kwargs["retries"] = args.retries
    return kwargs


def _check_watch_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.watch is None:
        return
    if args.watch < MIN_WATCH_INTERVAL:
        parser.error(f"--watch must be at least {MIN_WATCH_INTERVAL:g} seconds")
    if args.no_history:
        parser.error("--watch compares against scan history, so it can't be used with --no-history")
    if args.output or args.stream_jsonl:
        parser.error(
            "--watch prints alerts, not results; it can't be used with --output or --stream-jsonl"
        )


def _collect_devices(
    network: str,
    args: argparse.Namespace,
    port_options: dict[str, Any],
    scan_kwargs: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """One full pass: ARP sweep, conflict check, enrichment and (if asked)
    the port scan. None if the sweep could not run (no privileges)."""
    devices = _scan_or_none(network, **scan_kwargs)
    if devices is None:
        return None

    conflicts = find_ip_conflicts(devices)
    if conflicts:
        print_conflicts(conflicts)

    enrich_devices(devices)

    if args.scan_ports:
        if args.async_scan:
            scan_devices_ports_async(devices, **port_options)
        else:
            scan_devices_ports(
                devices, method="syn" if args.syn_scan else "connect", **port_options
            )
    return devices


def _watch(
    network: str,
    args: argparse.Namespace,
    port_options: dict[str, Any],
    scan_kwargs: dict[str, Any],
) -> int:
    """Scan every `args.watch` seconds until Ctrl-C, alerting on changes."""
    gateway_ip = get_default_gateway()
    print(f"Watching {network} every {args.watch:g}s (Ctrl-C to stop).")
    if gateway_ip is None:
        print(
            "No default gateway found - gateway MAC changes will be reported as plain MAC changes."
        )

    try:
        while True:
            devices = _collect_devices(network, args, port_options, scan_kwargs)
            if devices is None:
                return 1

            entry = load_history(args.history_file).get(network)
            previous_devices = entry["devices"] if entry else []
            known = known_device_macs(entry)
            alerts = detect_changes(previous_devices, devices, known, gateway_ip)
            save_scan(args.history_file, network, devices)

            stamp = datetime.datetime.now().strftime("%H:%M:%S")
            if not previous_devices and not known:
                print(f"[{stamp}] {len(devices)} devices found - baseline recorded.")
            else:
                print(f"[{stamp}] {len(devices)} devices, {len(alerts)} alert(s).")
            print_alerts(alerts)

            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nStopped watching.")
        return 0


def run_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Run one CLI-mode scan and return a process exit code."""
    try:
        network = validate_network(args.network)
    except ValueError:
        parser.error(f"{args.network!r} is not a valid network address")

    port_options = _port_scan_options(args, parser)
    scan_kwargs = _arp_scan_kwargs(args, parser)
    _check_watch_flags(args, parser)

    if args.watch is not None:
        return _watch(network, args, port_options, scan_kwargs)

    devices = _collect_devices(network, args, port_options, scan_kwargs)
    if devices is None:
        return 1

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


def main() -> int:
    check_npcap_on_windows()
    parser = build_arg_parser()
    args = parser.parse_args()
    check_privileges()

    if args.dashboard:
        from backend.app.server.server import run_dashboard

        run_dashboard(port=args.port)
        return 0

    if args.network is None:
        return run_interactive()

    return run_cli(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
