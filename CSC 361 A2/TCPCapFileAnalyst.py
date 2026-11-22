import sys
import struct

class GlobalHeader:
    def __init__(self, buffer):
        self.magic, self.ver_minor, self.ver_major, self.timezone, self.sig_figs, self.snap_len, self.net_type = struct.unpack('IHHiIII', buffer)

class PacketHeader:
    def __init__(self):
        self.timestamp_sec = 0
        self.timestamp_usec = 0
        self.incl_len = 0
        self.orig_len = 0

    def parse_header(self, buffer):
        self.timestamp_sec, self.timestamp_usec, self.incl_len, self.orig_len = struct.unpack('IIII', buffer)

class IPv4Header:
    def __init__(self):
        self.ihl = None
        self.total_len = None
        self.src_ip = None
        self.dst_ip = None

    def extract_ihl(self, value):
        self.ihl = (struct.unpack('B', value)[0] & 15) * 4

    def extract_total_len(self, buffer):
        self.total_len = struct.unpack('>H', buffer)[0]
    
    def extract_ip(self, src_buffer, dst_buffer):
        self.src_ip = '.'.join(map(str, struct.unpack('BBBB', src_buffer)))
        self.dst_ip = '.'.join(map(str, struct.unpack('BBBB', dst_buffer)))

class TCPHeader: 
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.urg_pointer = 0

    def extract_src_port(self, buffer):
        self.src_port = (buffer[0] << 8) + buffer[1]

    def extract_dst_port(self, buffer):
        self.dst_port = (buffer[0] << 8) + buffer[1]

    def extract_seq_num(self, buffer):
        self.seq_num = struct.unpack(">I", buffer)[0]

    def extract_ack_num(self, buffer):
        self.ack_num = struct.unpack(">I", buffer)[0]

    def extract_data_offset(self, buffer):
        self.data_offset = ((struct.unpack("B", buffer)[0] & 240) >> 4) * 4

    def extract_flags(self, buffer):
        val = struct.unpack("B", buffer)[0]
        self.flags = {
            "FIN": val & 1,
            "SYN": (val & 2) >> 1,
            "RST": (val & 4) >> 2,
            "ACK": (val & 16) >> 4
        }

    def extract_window_size(self, buffer):
        self.window_size = struct.unpack(">H", buffer)[0]
    
class Packet:
    def __init__(self):
        self.header = PacketHeader()
        self.ipv4 = IPv4Header()
        self.tcp = TCPHeader()
        self.data = b''
        self.payload_size = 0
        self.timestamp = 0

    def parse_header(self, buffer):
        self.header.parse_header(buffer)

    def store_data(self, buffer):
        self.data = buffer

    def compute_timestamp(self, start_time):
        self.timestamp = round(self.header.timestamp_sec + self.header.timestamp_usec * 0.000001 - start_time, 6)

    def parse_ipv4(self):
        self.ipv4.extract_ihl(self.data[14:15])
        self.ipv4.extract_total_len(self.data[16:18])
        self.ipv4.extract_ip(self.data[26:30], self.data[30:34])

    def parse_tcp(self):
        offset = 14 + self.ipv4.ihl
        self.tcp.extract_src_port(self.data[offset+0: offset+2])
        self.tcp.extract_dst_port(self.data[offset+2: offset+4])
        self.tcp.extract_seq_num(self.data[offset+4: offset+8])
        self.tcp.extract_ack_num(self.data[offset+8: offset+12])
        self.tcp.extract_data_offset(self.data[offset+12: offset+13])
        self.tcp.extract_flags(self.data[offset+13: offset+14])
        self.tcp.extract_window_size(self.data[offset+14: offset+16])

    def store_payload_size(self, payload):
        self.payload_size = payload


#helper function for divisions by 0 just in case
def compute_mean(list):
    return round(sum(list) / len(list), 6) if list else 0


#helper function for printing conn details
def print_connection_details(idx, conn, pcap_start_time, tcp_reset_count, pre_existing_connections, tcp_complete, tcp_packets, tcp_window_sizes, rtt_values):
    """Helper function to print connection details and update statistics with improved RTT calculation."""
    
    first_packet, last_packet = None, None
    syn_count, fin_count, rst_count = 0, 0, 0
    src_to_dst, dst_to_src = [], []
    
    # Dictionary to track unacknowledged packets for RTT calculation
    unacked_packets = {}

    print(f'Connection {idx}:')
    
    for packet in conn:
        # Identify first and last packet of the connection
        if packet.tcp.flags['SYN'] == 1:
            if first_packet is None:
                first_packet = packet
            syn_count += 1
        
        if packet.tcp.flags['FIN'] == 1:
            fin_count += 1
            last_packet = packet
        
        if packet.tcp.flags['RST'] == 1:
            rst_count += 1

        packet.compute_timestamp(pcap_start_time)

        if first_packet and packet.ipv4.src_ip == first_packet.ipv4.src_ip:
            src_to_dst.append(packet)
        else:
            dst_to_src.append(packet)

        # store SYN timestamp 
        if packet.tcp.flags['SYN'] == 1 and packet.tcp.flags['ACK'] == 0:
            unacked_packets[packet.tcp.seq_num] = packet.timestamp

        #SYN-ACK RTT
        if packet.tcp.flags['SYN'] == 1 and packet.tcp.flags['ACK'] == 1:
            syn_ack_rtt = packet.timestamp - unacked_packets.get(packet.tcp.ack_num - 1, float('inf'))
            if syn_ack_rtt > 0:
                rtt_values.append(syn_ack_rtt)

        # Store data packet timestamps 
        if packet.payload_size > 0:
            unacked_packets[packet.tcp.seq_num + packet.payload_size] = packet.timestamp

        # RTT when an ACK is received
        if packet.tcp.flags['ACK'] == 1 and packet.tcp.ack_num in unacked_packets:
            ack_rtt = packet.timestamp - unacked_packets[packet.tcp.ack_num]
            if ack_rtt > 0:
                rtt_values.append(ack_rtt)
            unacked_packets.pop(packet.tcp.ack_num,None)

    print(f'Source Address: {first_packet.ipv4.src_ip}')
    print(f'Destination Address: {first_packet.ipv4.dst_ip}')
    print(f'Source Port: {first_packet.tcp.src_port}')
    print(f'Destination Port: {first_packet.tcp.dst_port}')
    print(f'Status: S{syn_count}F{fin_count}')

    if rst_count > 0:
        tcp_reset_count[0] += 1

    # Check if the first packet in the connection is not SYN (should mean a pre-existing connection?) DOUBLE CHECK THIS W TA
    if first_packet.tcp.flags['SYN'] == 0:
        pre_existing_connections[0] += 1

    if last_packet is not None:
        duration = last_packet.timestamp - first_packet.timestamp

        print(f'Start Time: {first_packet.timestamp} seconds')
        print(f'End Time: {last_packet.timestamp} seconds')
        print(f'Duration: {round(duration, 6)} seconds')

        tcp_complete.append(duration)
        tcp_packets.append(len(src_to_dst) + len(dst_to_src))

        src_bytes = sum(pkt.payload_size for pkt in src_to_dst)
        dst_bytes = sum(pkt.payload_size for pkt in dst_to_src)

        print(f'Number of packets ssent from Source to Destination: {len(src_to_dst)}')
        print(f'Number of packets sent from Destination to Source: {len(dst_to_src)}')
        print(f'Total number of Packets: {len(src_to_dst) + len(dst_to_src)}')
        print(f'Number of bytes sent from Source to Destination: {src_bytes} bytes')
        print(f'Number of bytes sent from Destination to Source: {dst_bytes} bytes')
        print(f'Total number of data bytes: {src_bytes + dst_bytes} bytes')

        tcp_window_sizes.extend(pkt.tcp.window_size for pkt in conn)

    print('END')
    print('+++++++++++++++++++++++++++++++++')



def main():

    #Handle input file error
    if len(sys.argv) != 2:
        print('Please provide a capture file  as input')
        exit()

    filename = sys.argv[1]

    try:
        f = open(filename,'rb')

    except FileNotFoundError:
        print(f"Error:{filename} not found.", file = sys.stderr)
        sys.exit(1)
    
    # Read global heade
    global_hdr = GlobalHeader(f.read(24))
    if global_hdr.magic != 2712847316:
        exit("Magic Number Error.")

    connection_dict = {} 

    pcap_start_time = None

    while True:
        # Read packet header
        stream = f.read(16)
        if stream == b'': break

        packet = Packet()
        packet.parse_header(stream)
        incl_len = packet.header.incl_len

        if pcap_start_time is None:
            pcap_start_time = round(packet.header.timestamp_sec + packet.header.timestamp_usec * 0.000001, 6)

        packet.store_data(f.read(incl_len))
        packet.parse_ipv4()
        packet.parse_tcp()

        # Get payload size PREVENT POTENTIAL NEGATIVE PADDING
        payload = packet.header.incl_len - 14 - packet.ipv4.ihl - packet.tcp.data_offset
        padding = max(0, packet.header.incl_len - packet.ipv4.total_len - 14)
        if payload < 42:
            payload = 0

        packet.store_payload_size(payload + padding)

        # Create connection key and add packet to correct connection key, if none found then add a new key for that connection
        connection_key = tuple(sorted([(packet.ipv4.src_ip, packet.tcp.src_port), (packet.ipv4.dst_ip, packet.tcp.dst_port)]))
        if connection_key not in connection_dict:
            connection_dict[connection_key] = [] 

        packet.number = len(connection_dict[connection_key]) + 1

        connection_dict[connection_key].append(packet)

    f.close()

    # TCP statistics init
    tcp_total = len(connection_dict)
    tcp_complete = []
    tcp_packets = []
    tcp_window_sizes = []
    tcp_reset_count = [0]  
    rtt_values = []
    pre_existing_connections = [0]  

    print('A) Total number of connections:', tcp_total)
    print('______________________________________\n')

    print('B) Connections Details:\n')

    for idx, conn in enumerate(connection_dict.values(), start=1):
        print_connection_details(idx, conn, pcap_start_time, tcp_reset_count, pre_existing_connections, tcp_complete, tcp_packets, tcp_window_sizes, rtt_values)

    print('______________________________________\n')

    print('C) General:\n')
    print(f'The total number of complete TCP connections: {len(tcp_complete)}')
    print(f'The number of Reset TCP connections: {tcp_reset_count[0]}')
    print(f'The number of TCP connections still open when the trace capture ended: {tcp_total - len(tcp_complete)}')
    print(f'The number of TCP connections established before Capture Started: {pre_existing_connections[0]}')

    print('______________________________________\n')

    if tcp_complete:
        print('D) Complete TCP Connections:\n')

        print('Minimum time Duration:', round(min(tcp_complete), 6), 'seconds')
        print(f'Mean time Duration: {compute_mean(tcp_complete)} seconds')
        print('Maximum time Duration:', round(max(tcp_complete), 6), 'seconds')

        if rtt_values:
            print('\nMinimum RTT value:', round(min(rtt_values), 6), 'seconds')
            print(f'Mean RTT value:{compute_mean(rtt_values)} seconds')
            print('Maximum RTT value:', round(max(rtt_values), 6), 'seconds')

        if tcp_packets:
            print('\nMinimum number of packets including both send/received', min(tcp_packets))
            print('Mean number of packets including both send/received:', round(sum(tcp_packets) / len(tcp_packets), 6))
            print('Maximum number of packets including both send/received', max(tcp_packets))

        if tcp_window_sizes:
            print('\nMinimum receive window size including both send/received:', min(tcp_window_sizes))
            print('Mean receive window size including both send/received:', round(sum(tcp_window_sizes) / len(tcp_window_sizes), 6))
            print('Maximum receive window size including both sned/received', max(tcp_window_sizes))

    print('______________________________________\n')


if __name__ == "__main__":
    main()


