from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, Raw

# ---------------- GENERIC CHECKSUM FUNCTION ----------------
def calc_checksum(data_bytes):
    if len(data_bytes) % 2:
        data_bytes += b'\x00'
    s = 0
    for i in range(0, len(data_bytes), 2):
        s += (data_bytes[i] << 8) + data_bytes[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

# ---------------- READ PCAP ----------------
packets = rdpcap("checksum.pcapng")

# ---------------- TABLE HEADER ----------------
print(f"{'Frame':<6} {'Protocol':<8} {'Src IP':<15} {'Dst IP':<15} "
      f"{'IP Match':<9} {'TCP Match':<10} {'UDP Match':<10} {'ICMP Match':<11} {'TLS':<5}")

# ---------------- LOOP THROUGH PACKETS ----------------
for i, pkt in enumerate(packets, start=1):

    proto = "-"
    ip_match = tcp_match = udp_match = icmp_match = "-"
    tls_flag = "No"

    # ---------------- ETHERNET ----------------
    if Ether in pkt:
        eth = pkt[Ether]
        proto = eth.type

    # ---------------- IP CHECKSUM ----------------
    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        header_len = ip.ihl * 4
        ip_bytes = bytes(ip)[:header_len]
        ip_zero = ip_bytes[:10] + b"\x00\x00" + ip_bytes[12:]
        ip_calc = calc_checksum(ip_zero)

        ip_match = "Yes" if ip_calc == ip.chksum else "No"

        # ---------------- TCP CHECKSUM ----------------
        if TCP in ip:
            proto = "TCP"
            tcp = ip[TCP]

            tcp_bytes = bytearray(bytes(tcp))
            tcp_bytes[16:18] = b"\x00\x00"

            src_ip = bytes(map(int, ip.src.split('.')))
            dst_ip = bytes(map(int, ip.dst.split('.')))
            pseudo = src_ip + dst_ip + bytes([0, ip.proto]) + len(tcp_bytes).to_bytes(2, 'big')

            tcp_calc = calc_checksum(pseudo + bytes(tcp_bytes))
            tcp_match = "Yes" if tcp_calc == tcp.chksum else "No"

            # -------- TLS DETECTION --------
            if tcp.dport == 443 or tcp.sport == 443:
                if Raw in tcp:
                    tls_flag = "Yes"

        # ---------------- UDP CHECKSUM ----------------
        elif UDP in ip:
            proto = "UDP"
            udp = ip[UDP]

            udp_bytes = bytearray(bytes(udp))
            udp_bytes[6:8] = b"\x00\x00"

            src_ip = bytes(map(int, ip.src.split('.')))
            dst_ip = bytes(map(int, ip.dst.split('.')))
            pseudo = src_ip + dst_ip + bytes([0, ip.proto]) + len(udp_bytes).to_bytes(2, 'big')

            udp_calc = calc_checksum(pseudo + bytes(udp_bytes))
            udp_match = "Yes" if udp_calc == udp.chksum else "No"

        # ---------------- ICMP CHECKSUM ----------------
        elif ICMP in ip:
            proto = "ICMP"
            icmp = ip[ICMP]

            icmp_bytes = bytearray(bytes(icmp))
            icmp_bytes[2:4] = b"\x00\x00"

            icmp_calc = calc_checksum(bytes(icmp_bytes))
            icmp_match = "Yes" if icmp_calc == icmp.chksum else "No"

    else:
        src = dst = "-"

    # ---------------- PRINT OUTPUT ----------------
    print(f"{i:<6} {proto:<8} {src:<15} {dst:<15} "
          f"{ip_match:<9} {tcp_match:<10} {udp_match:<10} {icmp_match:<11} {tls_flag:<5}")
