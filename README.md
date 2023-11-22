<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
# Table of Contents

- [Network Scanner](#network-scanner)
- [Requirements](#requirements)
- [Usage](#usage)
- [Example](#example)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Network Scanner

This project is a network scanner that can scan a local network and identify the
IP addresses and MAC addresses of all connected devices. It uses the **scapy**
library, which is a powerful tool for creating and manipulating network packets.
Another important module is the **rich** module which provides colourised output
to produce error message to the user. It also uses the **ipaddress** module,
which provides functions for working with IP addresses and networks.

# Requirements

To run this project, you will to install necessary depencies by:

```bash
$ pip install -r requirements.txt
```

The ipaddress module is included in the standard library of Python 3.

# Usage

To use this project, you can run the script main.py from the command
line as root:

```bash
$ sudo python main.py
```

The script will ask you to enter the network address that you want to scan, such
as 192.168.1.0/24. The network address must be a valid IP address or network,
otherwise the script will raise an error. The script will then send ARP requests
to all devices on the network and capture the ARP responses. The script will
print the IP and MAC addresses of all devices that responded to the ARP
requests.

# Example

Here is an example of the output of the script:

```txt
Enter the network address (e.g., 192.168.1.0 or 192.168.1.0/24): 192.168.1.0/24

IP Address              MAC Address
-----------------------------------------
192.168.1.1             9c:5a:6b:1e:4f:0c
192.168.1.2             4a:7c:9f:3b:2d:8e
192.168.1.254           7d:3e:8a:5c:1b:9d
```
