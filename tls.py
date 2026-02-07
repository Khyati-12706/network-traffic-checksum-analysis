from scapy.all import rdpcap, IP, TCP

def calc_checksum(data_bytes):
    """Generic checksum calculation for IP/TCP"""
    if len(data_bytes) % 2:
        data_bytes += b'\x00'
    s = 0
    for i in range(0, len(data_bytes), 2):
        s += (data_bytes[i] << 8) + data_bytes[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# Read pcapng file
packets = rdpcap("checksum.pcapng")

# Print headings
print(f"{'Frame#':<7} {'Src IP':<16} {'Dst IP':<16} "
      f"{'IPv4 Calc':<12} {'IPv4 Orig':<12} {'IPv4 Match':<10} "
      f"{'TCP Calc':<12} {'TCP Orig':<12} {'TCP Match':<10} "
      f"{'TLS?':<6}")

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

        # ---------------- TCP CHECKSUM ----------------
        tls_flag = "No"

        if TCP in ip:
            tcp = ip[TCP]
            tcp_bytes = bytearray(bytes(tcp))
            tcp_bytes[16:18] = b"\x00\x00"

            # pseudo-header
            src_ip_bytes = bytes(map(int, ip.src.split('.')))
            dst_ip_bytes = bytes(map(int, ip.dst.split('.')))
            proto_byte = bytes([0, ip.proto])
            tcp_len_field = len(tcp_bytes).to_bytes(2, 'big')
            pseudo_header = src_ip_bytes + dst_ip_bytes + proto_byte + tcp_len_field

            tcp_calc = calc_checksum(pseudo_header + bytes(tcp_bytes))
            tcp_orig = tcp.chksum
            tcp_match = "Yes" if tcp_calc == tcp_orig else "No"

            # ---------------- TLS DETECTION ----------------
            # TLS runs over TCP port 443
            if tcp.sport == 443 or tcp.dport == 443:
                tls_flag = "TLS Found"


        else:
            tcp_calc = tcp_orig = tcp_match = "-"

        # Print frame info
        print(f"{i:<7} {ip.src:<16} {ip.dst:<16} "
              f"0x{ip_calc:04X}    0x{ip_orig:04X}    {ip_match:<10} "
              f"{('0x'+format(tcp_calc,'04X')) if tcp_calc!='-' else '-':<12} "
              f"{('0x'+format(tcp_orig,'04X')) if tcp_orig!='-' else '-':<12} "
              f"{tcp_match:<10} {tls_flag:<6}")
