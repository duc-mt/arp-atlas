"""
==============================================================================
Module Name:   enrichment.py
Description:   Source module enrichment.py.
Author:        Mai Tan Duc <ducmai.network@gmail.com>
Created:       2026-10-10
Version:       1.1.0
License:       MIT
==============================================================================
Usage:         python3 enrichment.py [options]
Notes:         Requires Python 3.8+
==============================================================================
"""

from __future__ import annotations

import asyncio
import functools
import gzip
import random
import socket
import struct
from pathlib import Path
from typing import Any

from backend.app.config import DEFAULT_HOSTNAME_TIMEOUT

# ==============================================================================
# Vendor / OUI resolution
# ==============================================================================
#
# scapy ships its own bundled copy of the IEEE manufacturer database, but it
# is only refreshed when scapy itself is upgraded, so newly-allocated OUI
# blocks (anything IEEE has registered since that snapshot was taken) come
# back as a miss - lookup_vendor() used to have no way to tell the two apart
# from "not a real OUI at all".
#
# To fix that without a network call on every lookup, we ship a small cache
# of our own (`backend/app/data/manuf.gz`, in Wireshark's `manuf` file
# format) and check it first. Only if *that* also misses do we fall back to
# scapy's bundled database, so nothing regresses for OUIs scapy already
# knows about.

_MANUF_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "manuf.gz"


def _normalize_oui(raw: str) -> str | None:
    """Normalise a MAC address or bare OUI to the canonical, upper-case,
    colon-separated 24-bit OUI form ("XX:XX:XX") used as this module's
    cache key.

    Accepts colons, dashes, dots, or no separator at all, in any case,
    and only looks at the first 3 octets - a full 48-bit MAC and a bare
    24-bit OUI both normalise to the same key.

    Returns None for anything that doesn't contain at least 6 valid hex
    digits (never raises).
    """
    hex_only = raw.replace(":", "").replace("-", "").replace(".", "").upper()
    hex_only = hex_only[:6]
    if len(hex_only) < 6:
        return None
    try:
        int(hex_only, 16)
    except ValueError:
        return None
    return ":".join(hex_only[i : i + 2] for i in range(0, 6, 2))


def _parse_manuf_lines(lines: list[str]) -> dict[str, str]:
    """Parse the body of a Wireshark `manuf` file into an OUI -> vendor
    mapping.

    The format is tab-separated: ``OUI<TAB>ShortName`` or
    ``OUI<TAB>ShortName<TAB>Full Descriptive Name`` (comment lines start
    with ``#``). We key on the normalised /24 OUI and take the most
    descriptive (last) column as the vendor name.

    CIDR-masked entries (e.g. ``00:1B:C5:00:00:00/36``, used for blocks
    smaller than a full /24) are skipped: every MAC we enrich here is a
    full 48-bit address, and matching those sub-/24 ranges correctly
    would need a longest-prefix match this cache doesn't need to do for
    the overwhelming majority of real-world devices.
    """
    db: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        oui_field, vendor = parts[0].strip(), parts[-1].strip()
        if "/" in oui_field or not vendor:
            continue
        oui = _normalize_oui(oui_field)
        if oui is not None:
            db[oui] = vendor
    return db


@functools.lru_cache(maxsize=1)
def _load_manuf_db() -> dict[str, str]:
    """Load and cache the local OUI -> vendor database once per process.

    Returns an empty dict (never raises) if the data file is missing or
    unreadable, so lookup_vendor() transparently falls back to scapy's
    bundled database with no behaviour change for anyone who hasn't
    fetched the file yet.
    """
    try:
        with gzip.open(_MANUF_DB_PATH, "rt", encoding="utf-8", errors="replace") as fh:
            return _parse_manuf_lines(fh.readlines())
    except OSError:
        return {}


def is_mac_randomized(mac: str) -> bool:
    """Return True if the MAC address's locally-administered bit is set
    (i.e. it is likely a randomised/privacy MAC rather than a
    hardware-burned OUI).
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def lookup_vendor(mac: str) -> str | None:
    """Look up the manufacturer that registered a MAC address's OUI.

    Checks our own cached copy of the Wireshark `manuf` database first
    (O(1), covers OUIs allocated after scapy's bundled database was last
    refreshed), then falls back to scapy's bundled IEEE manufacturer
    database (`scapy.conf.manufdb`) - no extra dependency and no network
    lookup on the hot path either way.

    Parameters
    ----------
    mac : str
        A MAC address, e.g. "9c:5a:6b:1e:4f:0c".

    Returns
    -------
    str or None
        The manufacturer name, or None if the OUI isn't in either
        database (common for locally-administered/randomised MACs).
    """
    oui = _normalize_oui(mac)
    if oui is not None:
        vendor = _load_manuf_db().get(oui)
        if vendor:
            return vendor

    import scapy.all as scapy  # type: ignore[import-untyped]

    vendor = scapy.conf.manufdb._get_manuf(mac)
    # scapy has no type stubs, so mypy sees `vendor` as Any here; narrow
    # it explicitly rather than returning Any from a str|None function.
    if not isinstance(vendor, str):
        return None
    # _get_manuf() echoes the input back unchanged when there's no
    # match, rather than raising or returning None itself.
    if vendor.lower() == mac.lower():
        return None
    return vendor


# ==============================================================================
# Hostname resolution
# ==============================================================================
#
# The original implementation only tried unicast reverse DNS, which depends
# on the LAN's DNS server having a PTR record for every DHCP lease - most
# home/office networks don't bother configuring that, so it silently
# resolved almost nothing. We now race four independent protocols for each
# IP and take whichever answers first with a usable name:
#
#   - Reverse DNS   (unicast, unchanged from before)
#   - mDNS          (multicast 224.0.0.251:5353 - Apple/Linux/Avahi/IoT/printers)
#   - LLMNR         (multicast 224.0.0.252:5355 - Windows)
#   - NBNS          (unicast UDP/137 NBSTAT    - Windows, Samba/NAS shares)


def _reverse_name(ip: str) -> str:
    """Build the "X.X.X.X.in-addr.arpa" PTR query name for an IPv4
    address, e.g. "192.168.1.50" -> "50.1.168.192.in-addr.arpa".
    """
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _build_dns_ptr_query(name: str, transaction_id: int) -> bytes:
    """Build a minimal, single-question DNS query packet asking for the
    PTR record of `name`. mDNS and LLMNR both reuse the plain DNS wire
    format for their questions, so this one builder serves both.
    """
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    question = b""
    for label in name.split("."):
        encoded = label.encode("ascii")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"  # root label
    question += struct.pack(">HH", 12, 1)  # QTYPE=PTR(12), QCLASS=IN(1)
    return header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Advance `offset` past a (possibly compressed) DNS name without
    decoding it, returning the offset of the field that follows.
    """
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer: always 2 bytes
            return offset + 2
        offset += 1 + length


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at `offset`.

    Returns the dotted name and the offset of the field immediately
    after it *in the original, non-jumped stream* (i.e. correct to
    resume parsing from even when the name used compression).
    """
    labels: list[str] = []
    jumped = False
    next_offset = offset
    for _ in range(128):  # generous bound against malformed/looping input
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            return ".".join(labels), next_offset
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            if not jumped:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumped = True
            continue
        start = offset + 1
        end = start + length
        labels.append(data[start:end].decode("ascii", errors="replace"))
        offset = end
    raise ValueError("name too deeply compressed")


def _parse_ptr_response(data: bytes, expected_id: int) -> str | None:
    """Pull the first PTR record's target out of a DNS/mDNS/LLMNR
    response packet, or return None if it doesn't parse as a clean,
    successful PTR answer.
    """
    if len(data) < 12:
        return None
    try:
        resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[0:8])
        # mDNS responses legitimately use transaction id 0; unicast DNS
        # and LLMNR echo back whatever id we sent.
        if resp_id not in (0, expected_id):
            return None
        if flags & 0x000F:  # non-zero RCODE
            return None
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(data, offset)
            offset += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
            offset += 10
            if rtype == 12:  # PTR
                name, _ = _decode_dns_name(data, offset)
                if name:
                    return name.rstrip(".")
            offset += rdlength
    except (struct.error, ValueError, IndexError):
        return None
    return None


class _DatagramResponseProtocol(asyncio.DatagramProtocol):
    """Hands the first UDP datagram received to a waiting Future.
    Shared by the mDNS, LLMNR, and NBNS probes below."""

    def __init__(self, result: asyncio.Future[bytes]) -> None:
        self._result = result

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self._result.done():
            self._result.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._result.done():
            self._result.set_exception(exc)


async def _reverse_dns_lookup(ip: str, timeout: float) -> str | None:
    """Unicast reverse DNS (PTR) lookup - unchanged from the original
    implementation."""
    loop = asyncio.get_running_loop()
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getnameinfo, (ip, 0), socket.NI_NAMEREQD),
            timeout=timeout,
        )
        return res[0]
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return None


async def _query_dns_like(
    name: str,
    *,
    multicast_addr: tuple[str, int],
    unicast_target: str,
    port: int,
    timeout: float,
) -> str | None:
    """Shared mDNS/LLMNR probe: both are plain DNS-format PTR queries
    over UDP, differing only in which multicast group and port they
    use. Sends to the device directly *and* to the protocol's
    multicast group (stacks vary in which one they answer on) and
    returns the first datagram that parses as a usable PTR answer,
    ignoring any unrelated chatter on the wire until `timeout` elapses.
    """
    loop = asyncio.get_running_loop()
    transaction_id = random.randint(0, 0xFFFF)  # nosec B311 - protocol transaction id, not a secret
    query = _build_dns_ptr_query(name, transaction_id)
    deadline = loop.time() + timeout
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            result: asyncio.Future[bytes] = loop.create_future()
            transport, _ = await loop.create_datagram_endpoint(
                functools.partial(_DatagramResponseProtocol, result),
                family=socket.AF_INET,
                allow_broadcast=True,
            )
            try:
                transport.sendto(query, (unicast_target, port))
                transport.sendto(query, multicast_addr)
                data = await asyncio.wait_for(result, timeout=remaining)
            finally:
                transport.close()
            name_found = _parse_ptr_response(data, transaction_id)
            if name_found:
                return name_found
            # Got a datagram but not our answer (e.g. unrelated mDNS
            # traffic) - loop again within whatever time is left.
    except (asyncio.TimeoutError, OSError):
        return None


async def _mdns_lookup(ip: str, timeout: float) -> str | None:
    return await _query_dns_like(
        _reverse_name(ip),
        multicast_addr=("224.0.0.251", 5353),
        unicast_target=ip,
        port=5353,
        timeout=timeout,
    )


async def _llmnr_lookup(ip: str, timeout: float) -> str | None:
    return await _query_dns_like(
        _reverse_name(ip),
        multicast_addr=("224.0.0.252", 5355),
        unicast_target=ip,
        port=5355,
        timeout=timeout,
    )


_NBNS_WILDCARD_NAME = b"*" + b"\x00" * 15  # the standard NBSTAT wildcard name


def _encode_netbios_name(name: bytes) -> bytes:
    """First-level NetBIOS name encoding (RFC 1002 S4.1): each of the 16
    raw name bytes is split into two nibbles, and each nibble is mapped
    onto 'A'..'P' by adding 0x41.
    """
    encoded = bytearray()
    for byte in name:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes(encoded)


def _build_nbns_query(transaction_id: int) -> bytes:
    """Build a NetBIOS Name Service Node Status (NBSTAT) wildcard query -
    the standard way to ask a host "what's your NetBIOS name?"."""
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    question = (
        struct.pack("B", 32)
        + _encode_netbios_name(_NBNS_WILDCARD_NAME)
        + b"\x00"
        + struct.pack(">HH", 0x21, 1)  # NBSTAT(0x21), IN(1)
    )
    return header + question


def _parse_nbns_response(data: bytes) -> str | None:
    """Pull the Workstation/Computer name (suffix 0x00, a unique - not
    group - name) out of an NBSTAT Node Status Response."""
    if len(data) < 13:
        return None
    try:
        _tid, _flags, qdcount, ancount = struct.unpack(">HHHH", data[0:8])
        if ancount < 1:
            return None
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(data, offset)
            offset += 4
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            return None
        rtype, _rclass, _ttl, _rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if rtype != 0x21 or offset >= len(data):
            return None
        num_names = data[offset]
        offset += 1
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset : offset + 15]
            suffix = data[offset + 15]
            name_flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
            offset += 18
            is_group_name = bool(name_flags & 0x8000)
            if suffix == 0x00 and not is_group_name:
                hostname = raw_name.decode("ascii", errors="replace").strip()
                if hostname:
                    return hostname
        return None
    except (struct.error, ValueError, IndexError):
        return None


async def _nbns_lookup(ip: str, timeout: float) -> str | None:
    """NetBIOS Name Service (UDP/137) Node Status probe - resolves the
    Workstation/Computer name advertised by Windows hosts and
    Samba-based NAS/file-share devices."""
    loop = asyncio.get_running_loop()
    transaction_id = random.randint(0, 0xFFFF)  # nosec B311 - protocol transaction id, not a secret
    query = _build_nbns_query(transaction_id)

    transport: asyncio.DatagramTransport | None = None
    try:
        result: asyncio.Future[bytes] = loop.create_future()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramResponseProtocol(result),
            family=socket.AF_INET,
        )
        transport.sendto(query, (ip, 137))
        data = await asyncio.wait_for(result, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        if transport is not None:
            transport.close()
    return _parse_nbns_response(data)


async def _lookup_hostname_async(ip: str, timeout: float) -> str | None:
    """Resolve a LAN hostname for `ip`, racing reverse DNS, mDNS, LLMNR
    and NBNS concurrently and returning whichever answers first with a
    usable name.

    Each protocol gets up to `timeout` seconds; because they all run at
    once (not one after another), a device that only speaks one of the
    four still resolves in roughly one timeout's worth of wall time, not
    four, and a device that answers quickly returns quickly instead of
    waiting for the slower protocols to finish.

    The four resolvers are called by name (rather than via a
    pre-built list of function references) so each one stays
    independently patchable in tests - exactly what lets
    test_enrich_devices.py mock the mDNS/NBNS legs individually.
    """
    loop = asyncio.get_running_loop()
    pending: set[asyncio.Task[str | None]] = {
        asyncio.ensure_future(_reverse_dns_lookup(ip, timeout)),
        asyncio.ensure_future(_mdns_lookup(ip, timeout)),
        asyncio.ensure_future(_llmnr_lookup(ip, timeout)),
        asyncio.ensure_future(_nbns_lookup(ip, timeout)),
    }
    deadline = loop.time() + timeout
    try:
        while pending:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            done, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    result = task.result()
                except Exception:  # nosec B112 - one probe failing just means try the next
                    continue
                if result:
                    return result
        return None
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


def lookup_hostname(ip: str, timeout: float = DEFAULT_HOSTNAME_TIMEOUT) -> str | None:
    """Attempt to resolve a hostname for an IP address via reverse DNS,
    mDNS, LLMNR, and NBNS (see `_lookup_hostname_async`).

    Parameters
    ----------
    ip : str
        The IP address to resolve.
    timeout : float
        Seconds to give each resolution protocol before giving up.

    Returns
    -------
    str or None
        The resolved hostname, or None if nothing answered in time.
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

    tasks = [_bounded_lookup(d["ip"], DEFAULT_HOSTNAME_TIMEOUT) for d in devices]
    hostnames = await asyncio.gather(*tasks)
    for d, h in zip(devices, hostnames, strict=False):
        d["hostname"] = h


def enrich_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add "vendor" and "hostname" fields to each device dict in place.

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
