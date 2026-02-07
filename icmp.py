from scapy.all import *

packets = rdpcap("checksum.pcapng")

for pkt in packets:
    if ICMP in pkt:
        print("ICMP Packet Found")
        print("Source IP:", pkt[IP].src)
        print("Destination IP:", pkt[IP].dst)
        print("ICMP Checksum:", pkt[ICMP].chksum)
        print("-----------------------------")
