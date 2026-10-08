#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
#
#        FILE:  main.py
#      AUTHOR:  Henry Mai <henryfromvietnam@gmail.com>
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

# Import ipaddress library
import ipaddress


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


# Define a function to print the results
def print_results(devices):
    if not devices:
        print('\nNo devices found.')
        return
    # Print the header
    print(
        "\nIP Address",
        "MAC Address",
        sep="\t\t",
        end="\n" + "-" * 41 + "\n",
    )
    # Loop through the devices
    for device in devices:
        # Print the IP and MAC addresses
        print(device["ip"], device["mac"], sep="\t\t")


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

    print_results(devices)


# --------------------------- Call the Main Function --------------------------
if __name__ == '__main__':
    main()
