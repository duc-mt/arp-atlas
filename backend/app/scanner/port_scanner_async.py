"""
==============================================================================
Module Name:   port_scanner_async.py
Description:   Async TCP connect port scanner with a hard cap on concurrently
               open sockets. Same results and device-dict contract as the
               threaded classifier.scan_devices_ports(); stdlib only.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-20
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         scan_devices_ports_async(devices)   # from synchronous code
               await async_scan_devices_ports(devices)   # from a coroutine
Notes:         Requires Python 3.10+. TCP connect only - the SYN scan needs
               scapy, which isn't async-native, so --syn-scan keeps using
               classifier.scan_devices_ports().
==============================================================================
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from backend.app.config import (
    ASYNC_FD_CAP,
    ASYNC_HOST_CONCURRENCY,
    COMMON_PORTS,
    SNMP_PORT,
)
from backend.app.scanner.classifier import classify_device, snmp_probe

logger = logging.getLogger(__name__)


async def _probe_port(
    ip: str,
    port: int,
    timeout: float,
    fd_semaphore: asyncio.Semaphore,
) -> int | None:
    """Try one TCP connect; the port number if it succeeds, else None.

    Refused, unreachable and timed-out connections are all "not open", so
    this never raises for network reasons.
    """
    async with fd_semaphore:
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            if writer is not None:
                writer.close()
                # A peer that already reset the connection has nothing left to close.
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        return port


async def async_scan_device_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 0.3,
    *,
    fd_semaphore: asyncio.Semaphore | None = None,
    snmp: bool = False,
) -> list[int]:
    """Async counterpart of classifier.scan_device_ports() (connect method).

    All of `ports` are probed concurrently, bounded by `fd_semaphore`.
    Pass one semaphore to share a socket budget across several devices;
    if omitted, a fresh one sized `ASYNC_FD_CAP` bounds this call alone.
    The semaphore is never cached at module level: it belongs to the
    event loop that created it, and a reused one breaks the next
    `asyncio.run()`.

    Returns the open ports in the order given, then 161 if `snmp` is set
    and an SNMP agent answered (see classifier.snmp_probe).
    """
    ports = COMMON_PORTS if ports is None else ports
    semaphore = fd_semaphore or asyncio.Semaphore(ASYNC_FD_CAP)

    results = await asyncio.gather(*(_probe_port(ip, port, timeout, semaphore) for port in ports))
    open_ports = [port for port in results if port is not None]

    if snmp and SNMP_PORT not in open_ports:
        # snmp_probe() is a blocking UDP round trip; keep it off the loop.
        loop = asyncio.get_running_loop()
        if await loop.run_in_executor(None, snmp_probe, ip, timeout):
            open_ports.append(SNMP_PORT)
    return open_ports


async def async_scan_devices_ports(
    devices: list[dict[str, Any]],
    ports: list[int] | None = None,
    timeout: float = 0.3,
    *,
    fd_cap: int = ASYNC_FD_CAP,
    host_concurrency: int = ASYNC_HOST_CONCURRENCY,
    progress_callback: Any = None,
    snmp: bool = False,
) -> list[dict[str, Any]]:
    """Add "open_ports" and "role" to each device dict in place, like
    classifier.scan_devices_ports(), but on the event loop.

    Parameters
    ----------
    devices : list[dict]
        As returned by scan_network()/enrich_devices().
    ports : list[int] or None
        Ports to probe. Defaults to COMMON_PORTS.
    timeout : float
        Per-port connect timeout in seconds. This is the *port* timeout
        (default 0.3), not the ARP reply timeout.
    fd_cap : int
        Most sockets open at once across all devices.
    host_concurrency : int
        Most devices in flight at once, which bounds how many probe tasks
        exist at a time (the socket cap alone doesn't).
    progress_callback : callable or None
        Called as fn(completed, total, device) after each device. An
        exception it raises is logged and does not abort the scan.
    snmp : bool
        Also probe SNMP (UDP/161) on each device.
    """
    ports = COMMON_PORTS if ports is None else ports
    fd_semaphore = asyncio.Semaphore(fd_cap)
    host_semaphore = asyncio.Semaphore(host_concurrency)
    total = len(devices)
    completed = 0

    async def _scan_one(device: dict[str, Any]) -> None:
        nonlocal completed
        async with host_semaphore:
            open_ports = await async_scan_device_ports(
                device["ip"], ports, timeout, fd_semaphore=fd_semaphore, snmp=snmp
            )
        device["open_ports"] = open_ports
        device["role"] = classify_device(device.get("vendor"), open_ports)
        completed += 1
        if progress_callback:
            try:
                progress_callback(completed, total, device)
            except Exception:
                logger.warning("progress_callback raised; continuing the scan", exc_info=True)

    await asyncio.gather(*(_scan_one(device) for device in devices))
    return devices


def scan_devices_ports_async(
    devices: list[dict[str, Any]],
    ports: list[int] | None = None,
    timeout: float = 0.3,
    *,
    fd_cap: int = ASYNC_FD_CAP,
    host_concurrency: int = ASYNC_HOST_CONCURRENCY,
    progress_callback: Any = None,
    snmp: bool = False,
) -> list[dict[str, Any]]:
    """Blocking wrapper around async_scan_devices_ports() for synchronous
    callers such as the CLI. Raises RuntimeError if called from a thread
    that already has a running event loop - await
    async_scan_devices_ports() there instead.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "scan_devices_ports_async() can't run inside a running event loop; "
            "await async_scan_devices_ports() instead"
        )
    return asyncio.run(
        async_scan_devices_ports(
            devices,
            ports,
            timeout,
            fd_cap=fd_cap,
            host_concurrency=host_concurrency,
            progress_callback=progress_callback,
            snmp=snmp,
        )
    )
