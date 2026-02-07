from scapy.all import *

packets = rdpcap("checksum.pcapng")

for i, pkt in enumerate(packets):
    if Ether in pkt:
        print("Packet No:", i)
        print("Ethernet Frame Found")
        print("Source MAC:", pkt[Ether].src)
        print("Destination MAC:", pkt[Ether].dst)
        print("Type:", pkt[Ether].type)
        print("-----------------------------")
