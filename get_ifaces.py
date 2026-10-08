import scapy.all as scapy
for ifc in scapy.get_working_ifaces():
    print(ifc.name, ifc.ip, ifc.network_name)
