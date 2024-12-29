import socket
import struct
import textwrap
import sys

# Function to format multi-line strings
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return formatted IP address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP Segment
def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def main():
    print("_____________________________________________")
    print("_____________________________________________")
    print(" ____     ___    ___   ____     ___     ____ ")
    print("|  _ \   / _ \  |_ _| |  _ \   / _ \   / ___|")
    print("| |_) | | | | |  | |  | | | | | | | | | |  _ ")
    print("|  __/  | |_| |  | |  | |_| | | |_| | | |_| |")
    print("|_|      \___/  |___| |____/   \___/   \____|")
    print("_____________________________________________")
    print("_____________________________________________")
    print("\n")
    print("network_analyser.py")
    print("/"*90)
    print("**Note:** This program will capture network packets and provide you with details about the packets. \nAnd this a very simple program to capture network packets and provide you with details about the packets \nDon't use this program for real network packet capture in real life situations.")
    print("/"*90)
    platform = sys.platform
    conn = None

    if platform.startswith("linux"):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    elif platform.startswith("win32"):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    elif platform.startswith("darwin"):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    if not conn:
        print("Unsupported platform.")
        sys.exit()

    packet_count = int(input("Enter the number of packets to capture (0 for infinite): "))

    print("Starting packet capture... Press Ctrl+C to stop.")
    try:
        count = 0
        while packet_count == 0 or count < packet_count:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                print('IPv4 Packet:')
                print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(f'Protocol: {proto}, Source: {src}, Target: {target}')

                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('ICMP Packet:')
                    print(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                    print(f'Data:')
                    print(format_multi_line('\t', data))

                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    print('TCP Segment:')
                    print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                    print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                    print(f'Flags:')
                    print(f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                    print(f'Data:')
                    print(format_multi_line('\t', data))

                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print('UDP Segment:')
                    print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                    print(f'Data:')
                    print(format_multi_line('\t', data))

            count += 1

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
        if platform.startswith("win32"):
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

if __name__ == "__main__":
    main()
