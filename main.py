#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
#
#        FILE:  main.py
#      AUTHOR:  Henry Mai <ducmai.network@gmail.com>
#       USAGE:  sudo python3 main.py
#               and identify the IP addresses and MAC addresses
#               of all connected devices.
# DESCRIPTION:  A network scanner that can scan a local network
#               and identify the IP addresses and MAC addresses
#               of all connected devices.
#     CREATED:  2023-11-22
#   I hereby declare that I completed this work without any improper help
#   from a third party and without using any aids other than those cited.
#
# =============================================================================


# ------------------------------- Module Imports ------------------------------
# Import scapy library
import scapy.all as scapy

# Import the necessary classes from the rich module
from rich.console import Console
from rich.theme import Theme

# Stdlib
import collections
import ipaddress
import socket


# ---------------------------- Function Definitions ---------------------------
def validate_network(network):
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
    ipaddress.ip_network(network, strict=False)

    return network


# Define a function to scan a network
def scan_network(network):
    # Create an ARP request packet with the network address
    # ARP is used to map IP addresses to MAC addresses
    # pdst is the parameter for the destination IP address
    arp_request = scapy.ARP(pdst=network)
    # Create an Ethernet broadcast packet
    # Ethernet is a protocol for data transmission over a network
    # dst is the parameter for the destination MAC address
    # ff:ff:ff:ff:ff:ff is the MAC address for broadcasting to all devices
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP request and the Ethernet broadcast
    # This creates a packet asking all network devices for their MAC addresses
    arp_broadcast = broadcast / arp_request
    # Send and receive the packets and store the results
    # srp is a function from scapy that sends and receives packets at layer 2
    # timeout is the parameter for how long to wait for a response
    # verbose is the parameter for whether to print the details of the packets
    answered, unanswered = scapy.srp(arp_broadcast, timeout=1, verbose=False)
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


def lookup_vendor(mac):
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
    vendor = scapy.conf.manufdb._get_manuf(mac)
    # _get_manuf() echoes the input back unchanged when there's no
    # match, rather than raising or returning None itself.
    if vendor.lower() == mac.lower():
        return None
    return vendor


def lookup_hostname(ip, timeout=0.3):
    """Attempt a reverse DNS lookup for an IP address.

    Parameters
    ----------
    ip : str
        The IP address to resolve.
    timeout : float
        Seconds to wait before giving up on this one lookup. Kept
        short and per-lookup (rather than left unbounded) since these
        run serially, one per discovered device, and most home/guest
        networks have no PTR records for most hosts at all.

    Returns
    -------
    str or None
        The resolved hostname, or None if there's no PTR record, the
        lookup times out, or DNS is unreachable - all routine outcomes
        for a reverse lookup, not error conditions worth surfacing.
    """
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def enrich_devices(devices):
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
        device["hostname"] = lookup_hostname(device["ip"])
    return devices


def find_ip_conflicts(devices):
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


# Define a function to print the results
def print_results(devices):
    if not devices:
        print('\nNo devices found.')
        return
    # Print the header
    print(
        "\nIP Address",
        "MAC Address",
        "Vendor",
        "Hostname",
        sep="\t\t",
        end="\n" + "-" * 70 + "\n",
    )
    # Loop through the devices
    for device in devices:
        # Vendor/hostname are only present once enrich_devices() has
        # run; fall back to "-" so this still works for a plain,
        # un-enriched device list (e.g. in tests).
        vendor = device.get("vendor") or "-"
        hostname = device.get("hostname") or "-"
        print(device["ip"], device["mac"], vendor, hostname, sep="\t\t")


def print_conflicts(conflicts):
    """Print a warning for each IP address that answered from more
    than one MAC address - see find_ip_conflicts()."""
    for ip, macs in conflicts.items():
        print_error(
            f"WARNING: {ip} responded from multiple MAC addresses "
            f"({', '.join(macs)}) - possible IP conflict or ARP "
            "spoofing."
        )


def print_error(message):
    """Print an error message in red using rich, via a shared console."""
    custom_theme = Theme({"danger": "red"})
    console = Console(theme=custom_theme)
    console.print(message, style="danger")


# ------------------------------- Main Function -------------------------------
def main():
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
        return

    try:
        devices = scan_network(network)
    except PermissionError:
        # NOTE: previously unhandled - scanning requires raw-socket
        # access, which needs root privileges (per the README's own
        # "run as root" instruction). Without them, scapy.srp() raises
        # PermissionError, which used to crash with a raw traceback
        # instead of the same kind of friendly message every other
        # error in this script gets.
        print_error(
            "Permission denied. This script needs to send raw packets - "
            "try running it with sudo/as root."
        )
        return

    conflicts = find_ip_conflicts(devices)
    if conflicts:
        print_conflicts(conflicts)

    enrich_devices(devices)
    print_results(devices)


# --------------------------- Call the Main Function --------------------------
if __name__ == '__main__':
    main()
