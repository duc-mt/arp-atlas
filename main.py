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
    # Print the header
    print(
        "\n",
        "IP Address",
        "MAC Address",
        sep="\t\t\t",
        end="\n" + "-" * 41 + "\n",
    )
    # Loop through the devices
    for device in devices:
        # Print the IP and MAC addresses
        print(device["ip"], device["mac"], sep="\t\t")


# ------------------------------- Main Function -------------------------------
def main():
    # Ask the user to enter the network address
    network = input(
        "Enter the network address (e.g., 192.168.1.0 or 192.168.1.0/24): "
    )

    # Validate the network address using ipaddress.ip_network()
    try:
        # This will raise a ValueError if the input is not
        # a valid IP address (192.168.1.0) or a network range (192.168.1.0/24)
        ip_network = ipaddress.ip_network(network)  # noqa: F841
        # Scan the network and store the results
        devices = scan_network(network)
        # Print the results
        print_results(devices)
    except ValueError:
        # Print an error message
        # Define a custom theme named "danger"
        custom_theme = Theme({"danger": "red"})
        # Create a Console object with the custom theme
        console = Console(theme=custom_theme)
        # Print error text in the "danger" style
        console.print(f"{network} is not a valid network address. Please enter a valid IP address or network.", style="danger",)  # noqa: E501


# --------------------------- Call the Main Function --------------------------
if __name__ == '__main__':
    main()
