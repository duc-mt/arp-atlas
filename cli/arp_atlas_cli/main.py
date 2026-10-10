
"""
==============================================================================
Module Name:   main.py
Description:   ARP Atlas command-line interface.  Entry point: ``sudo python -m cli.arp_atlas_cli.main``  or the ``arp-atlas`` console script installed via cli/pyproject.toml.
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
import json
import os
import sys
from typing import Any

from backend.app.config import DEFAULT_TIMEOUT, HISTORY_FILE
from backend.app.scanner.arp_scanner import scan_network, validate_network
from backend.app.scanner.classifier import scan_devices_ports
from backend.app.services.conflict_service import find_ip_conflicts
from backend.app.services.enrichment import enrich_devices
from backend.app.services.export_service import export_devices
from backend.app.services.history_service import diff_devices, load_history, save_scan
from cli.arp_atlas_cli.formatters import (
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
    if isinstance(exc, PermissionError):
        return True
    return type(exc).__name__ == "Scapy_Exception" and "Permission" in str(exc)


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
        help="Also probe a handful of common ports on each device and guess its role. "
        "Adds noticeable time per device, so this is opt-in.",
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


def run_cli(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Run one CLI-mode scan and return a process exit code."""
    try:
        network = validate_network(args.network)
    except ValueError:
        parser.error(f"{args.network!r} is not a valid network address")

    devices = _scan_or_none(network, timeout=args.timeout)
    if devices is None:
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


def main() -> int:
    check_npcap_on_windows()
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.dashboard:
        from backend.app.server.server import run_dashboard

        run_dashboard(port=args.port)
        return 0

    if args.network is None:
        return run_interactive()

    return run_cli(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
