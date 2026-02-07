from scapy.all import rdpcap, IP, UDP

def calc_checksum(data_bytes):
    """Generic checksum calculation for IP/UDP"""
    if len(data_bytes) % 2:
        data_bytes += b'\x00'
    s = 0
    for i in range(0, len(data_bytes), 2):
        s += (data_bytes[i] << 8) + data_bytes[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

# Read pcapng
packets = rdpcap("checksum.pcapng")

# Headings
print(f"{'Frame#':<7} {'Src IP':<16} {'Dst IP':<16} {'UDP Src Port':<12} {'UDP Dst Port':<12} {'IPv4 Calc':<10} {'IPv4 Orig':<10} {'IPv4 Match':<10} {'UDP Calc':<10} {'UDP Orig':<10} {'UDP Match':<10}")

# Loop through packets
for i, pkt in enumerate(packets, start=1):
    if IP in pkt:
        ip = pkt[IP]

        # ---------------- IPv4 CHECKSUM ----------------
        header_len = ip.ihl * 4
        ip_bytes = bytes(ip)[:header_len]
        ip_bytes_zero = ip_bytes[:10] + b"\x00\x00" + ip_bytes[12:]
        ip_calc = calc_checksum(ip_bytes_zero)
        ip_orig = ip.chksum
        ip_match = "Yes" if ip_calc == ip_orig else "No"

        # ---------------- UDP CHECKSUM ----------------
        if UDP in ip:
            udp = ip[UDP]
            udp_bytes = bytearray(bytes(udp))
            udp_bytes[6:8] = b"\x00\x00"  # zero checksum field for calculation

            # pseudo-header
            src_ip_bytes = bytes(map(int, ip.src.split('.')))
            dst_ip_bytes = bytes(map(int, ip.dst.split('.')))
            proto_byte = bytes([0, ip.proto])
            udp_len_field = len(udp_bytes).to_bytes(2, 'big')
            pseudo_header = src_ip_bytes + dst_ip_bytes + proto_byte + udp_len_field

            udp_calc = calc_checksum(pseudo_header + bytes(udp_bytes))
            udp_orig = udp.chksum
            udp_match = "Yes" if udp_calc == udp_orig else "No"
        else:
            udp_calc = udp_orig = udp_match = "-"
        
        # Print results
        src_port = udp.sport if UDP in ip else "-"
        dst_port = udp.dport if UDP in ip else "-"
        print(f"{i:<7} {ip.src:<16} {ip.dst:<16} {src_port:<12} {dst_port:<12} 0x{ip_calc:04X}    0x{ip_orig:04X}    {ip_match:<10} 0x{udp_calc if udp_calc!='-' else '-':<10} 0x{udp_orig if udp_orig!='-' else '-':<10} {udp_match:<10}")
