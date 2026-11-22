
import sys
import struct

#packet extraction classes from P2

class GlobalHeader:

	magic_number = None		# uint32
	version_minor = None		# uint16
	version_major = None		# uint16
	thiszone = None			# int32
	sigfigs = None			# uint32
	snaplen = None			# uint32
	network = None			# uint32

	def __init__(self, buffer):
		self.magic_number, self.version_minor, self.version_major, self.thiszone, self.sigfigs, self.snaplen, self.network = struct.unpack('IHHiIII', buffer)

class PacketHeader:

	ts_sec = None			# uint32
	ts_usec = None			# uint32
	incl_len = None			# uint32
	orig_len = None			# uint32

	def __init__(self):
		self.ts_sec = 0
		self.ts_usec = 0
		self.incl_len = 0
		self. orig_len = 0

	def set_header(self, buffer):
		self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack('IIII', buffer)

class IPV4Header:

	ihl = None			# int
	total_length = None		# int
	identification = None		# int
	flags = None			# int
	fragment_offset = None		# int
	ttl = None			# int
	protocol = None			# int
	src_ip = None			# str
	dst_ip = None			# str

	def set_ihl(self, value):
		result = struct.unpack('B', value)[0]
		self.ihl = (result & 15) * 4

	def set_total_len(self, buffer):
		num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
		num2 = (buffer[0] & 15) * 16 * 16
		num3 = ((buffer[1] & 240) >> 4) * 16
		num4 = (buffer[1] & 15)
		self.total_length = num1 + num2 + num3 + num4
	
	def set_ip(self, buffer1, buffer2):
		src_addr = struct.unpack('BBBB', buffer1)
		dst_addr = struct.unpack('BBBB', buffer2)
		self.src_ip = str(src_addr[0]) + '.' + str(src_addr[1]) + '.' + str(src_addr[2]) + '.' + str(src_addr[3])
		self.dst_ip = str(dst_addr[0]) + '.' + str(dst_addr[1]) + '.' + str(dst_addr[2]) + '.' + str(dst_addr[3])

	def set_identification(self, buffer):
		result = struct.unpack('BB', buffer)
		self.identification = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_fragment_offset(self, buffer):
		num0 = hex(((buffer[0] & 224) >> 5))
		num1 = ((buffer[0] & 16) >> 4) * 16 * 16 * 16
		num2 = (buffer[0] & 15) * 16 * 16
		num3 = ((buffer[1] & 240) >> 4) * 16
		num4 = (buffer[1] & 15)
		self.flags = num0
		self.fragment_offset = (num1 + num2 + num3 + num4) * 8

	def set_ttl(self, buffer):
		self.ttl = struct.unpack('B', buffer)[0]

	def set_protocol(self, buffer):
		self.protocol = struct.unpack('B', buffer)[0]
		
class UDPHeader:
	
	src_port = None
	dst_port = None
	udp_length = None
	checksum = None

	def set_src_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_dst_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_udp_len(self, buffer):
		result = struct.unpack('BB', buffer)
		self.udp_length = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_checksum(self, buffer):
		result = struct.unpack('BB', buffer)
		self.checksum = str(hex(result[0])) + str(hex(result[1]))
		
class ICMPHeader:

	type_num = None
	code = None
	src_port = None
	dst_port = None
	sequence = None

	def set_type(self, buffer):
		result = struct.unpack('B', buffer)[0]
		self.type_num = int(result)

	def set_code(self, buffer):
		result = struct.unpack('B', buffer)[0]
		self.code = int(result)

	def set_src_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_dst_port(self, buffer):
		result = struct.unpack('BB', buffer)
		self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

	def set_sequence(self, buffer):
		result = struct.unpack('BB', buffer)
		self.sequence = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

class Packet:

	header = None			# PacketHeader
	ipv4 = None			# IPV4Header
	icmp = None			# ICMPHeader
	udp = None			# UDPHeader
	data = None			# byte
	payload = None			# int
	timestamp = None		# int

	def __init__(self):
		self.header = PacketHeader()
		self.ipv4 = IPV4Header()
		self.icmp = ICMPHeader()
		self.udp = UDPHeader()
		self.data = b''
		self.payload = 0
		self.timestamp = 0

	def set_header(self, buffer):
		self.header.set_header(buffer)

	def set_data(self, buffer):
		self.data = buffer

	def set_number(self, value):
		self.number = value

	def set_rtt(self, p):
		rtt = p.timestamp - self.timestamp
		self.RTT_value = round(rtt, 8)

	def set_timestamp(self, orig_time):
		seconds = self.header.ts_sec
		microseconds = self.header.ts_usec
		self.timestamp = 1000 * round(seconds + microseconds * 0.000000001 - orig_time, 6)

	def set_ipv4(self):
		offset = 14 # ethernet header length
		self.ipv4.set_ihl(self.data[offset+0: offset+1])
		self.ipv4.set_total_len(self.data[offset+2: offset+4])
		self.ipv4.set_identification(self.data[offset+4: offset+6])
		self.ipv4.set_fragment_offset(self.data[offset+6: offset+8])
		self.ipv4.set_ttl(self.data[offset+8: offset+9])
		self.ipv4.set_protocol(self.data[offset+9: offset+10])
		self.ipv4.set_ip(self.data[offset+12: offset+16], self.data[offset+16: offset+20])

	def set_icmp(self):
		offset = 14 + self.ipv4.ihl
		self.icmp.set_type(self.data[offset+0: offset+1])
		self.icmp.set_code(self.data[offset+1: offset+2])
		# windows
		if self.icmp.type_num == 8 or self.icmp.type_num == 0:
			self.icmp.set_sequence(self.data[offset+6: offset+8])
		#linux
		offset += 8 + self.ipv4.ihl
		if offset+4 <= self.header.incl_len:
			if self.icmp.type_num != 8 and self.icmp.type_num != 0:
				self.icmp.set_sequence(self.data[offset+6: offset+8]) # also windows
			self.icmp.set_src_port(self.data[offset+0: offset+2])
			self.icmp.set_dst_port(self.data[offset+2: offset+4])
		else:
			self.icmp.src_port = 0
			self.icmp.dst_port = 0		

	def set_udp(self):
		offset = 14 + self.ipv4.ihl
		self.udp.set_src_port(self.data[offset+0: offset+2])
		self.udp.set_dst_port(self.data[offset+2: offset+4])
		self.udp.set_udp_len(self.data[offset+4: offset+6])
		self.udp.set_checksum(self.data[offset+6: offset+8])

#Helper stuff 

def read_global_header(file):
    return GlobalHeader(file.read(24))

def read_packet_header(file):
    header_data = file.read(16)
    return header_data if header_data else None

def read_packet_data(file, incl_len):
    return file.read(incl_len)

def match_icmp_packets(packets):
    echo_requests = [p for p in packets if p.icmp.type_num == 8]
    replies = [p for p in packets if p.icmp.type_num in (0, 11)]
    return echo_requests, replies

def match_udp_icmp_pairs(udp_packets, icmp_packets):
    pairs = []
    for udp in udp_packets:
        for icmp in icmp_packets:
            if udp.udp.src_port == icmp.icmp.src_port:
                pairs.append((udp, icmp))
    return pairs

def compute_rtts(pairs, base_time):
    rtt_map = {}
    for udp, icmp in pairs:
        udp.set_timestamp(base_time)
        icmp.set_timestamp(base_time)
        rtt = icmp.timestamp - udp.timestamp
        ip = icmp.ipv4.src_ip
        if ip not in rtt_map:
            rtt_map[ip] = []
        rtt_map[ip].append(rtt)
    return rtt_map

def get_fragments(packets):
    fragments = {}
    for pkt in packets:
        ident = pkt.ipv4.identification
        fragments.setdefault(ident, []).append(pkt)
    return fragments

def calculate_rtt_stats(rtt_map, src_ip, intermediate_nodes):
    for i, hop_ip in enumerate(intermediate_nodes):
        times = rtt_map.get(hop_ip, [])
        if not times:
            continue
        avg = round(sum(times) / len(times), 6)
        std_dev = round((sum((t - avg) ** 2 for t in times) / len(times)) ** 0.5, 6)
        print(f"The avg RTT between {src_ip} and {hop_ip} is: {avg} ms, the s.d. is: {std_dev} ms")


def analyze_ttl(src_packets):
    ttl_dict = {}
    for pkt in src_packets:
        ttl = pkt.ipv4.ttl
        ttl_dict.setdefault(ttl, []).append(pkt)
    return {ttl: len(packets) for ttl, packets in sorted(ttl_dict.items())}


#Main

# Validate input
if len(sys.argv) != 2:
    print('Usage: python3 TraceRouteAnalyzer.py <file.cap>')
    sys.exit(1)

filename = sys.argv[1]
f = open(filename, 'rb')

global_header = read_global_header(f)

protocol_map = {1: 'ICMP', 17: 'UDP'}
protocol_used = {}

src_packets = []
dst_packets = []
packet_counter = 0
pcap_start_time = None

# Packet processing loop
while True:
    header_data = read_packet_header(f)
    if not header_data:
        break

    packet = Packet()
    packet.set_header(header_data)
    packet.set_number(packet_counter)
    packet_counter += 1

    incl_len = packet.header.incl_len

    if pcap_start_time is None:
        pcap_start_time = round(packet.header.ts_sec + packet.header.ts_usec * 1e-6, 6)

    packet.set_data(read_packet_data(f, incl_len))
    packet.set_ipv4()

    src_packets.append(packet)

    # Protocol-specific parsing
    proto = packet.ipv4.protocol
    if proto == 1:  # ICMP
        packet.set_icmp()
        dst_packets.append(packet)
        protocol_used[proto] = 'ICMP'
    elif proto == 17:  # UDP
        packet.set_udp()
        if 33434 <= packet.udp.dst_port <= 33529:
            protocol_used[proto] = 'UDP'

# Match probes and responses
intermediate_nodes = []
rtt_dict = {}

if any(p.icmp.type_num == 8 for p in dst_packets):  # Windows
    echo_reqs, echo_resps = match_icmp_packets(dst_packets)
    src_packets = echo_reqs
    dst_packets = echo_resps

    for req in src_packets:
        for resp in dst_packets:
            if req.icmp.sequence == resp.icmp.sequence:
                ip = resp.ipv4.src_ip
                if ip not in rtt_dict:
                    intermediate_nodes.append(ip)
                    rtt_dict[ip] = []
                req.set_timestamp(pcap_start_time)
                resp.set_timestamp(pcap_start_time)
                rtt_dict[ip].append(resp.timestamp - req.timestamp)

else:  # Linux
    matched_pairs = match_udp_icmp_pairs(src_packets, dst_packets)
    for udp, icmp in matched_pairs:
        ip = icmp.ipv4.src_ip
        if ip not in rtt_dict:
            intermediate_nodes.append(ip)
            rtt_dict[ip] = []
        udp.set_timestamp(pcap_start_time)
        icmp.set_timestamp(pcap_start_time)
        rtt_dict[ip].append(icmp.timestamp - udp.timestamp)

# Fragmentation screening
fragments_by_id = get_fragments(src_packets)
fragmented_count = sum(1 for frags in fragments_by_id.values() if len(frags) > 1) #COUNT IDS WHICH HAVE MORE THAN ONE 

#Outputting
print('The IP address of the source node:', src_packets[0].ipv4.src_ip)
print('The IP address of ultimate destination node:', src_packets[0].ipv4.dst_ip)

print('The IP addresses of the intermediate destination nodes:')
for i, node in enumerate(intermediate_nodes[:-1]):
    print(f'\trouter {i+1}: {node}')
print()

print('The values in the protocol field of IP headers:')
for proto in sorted(protocol_used):
    print(f'\t{proto}: {protocol_used[proto]}')
print()

if fragmented_count == 0:
    print('The number of fragments created from the original datagram is: 0')
    print('The offset of the last fragment is: 0\n')
else:
    for ident, frags in fragments_by_id.items():
        if len(frags) > 1:

            last_offset = max(pkt.ipv4.fragment_offset for pkt in frags)
            print(f'The number of fragments created from the original datagram {ident} is: {len(frags)}')
            print(f'The offset of the last fragment is: {last_offset}\n')

calculate_rtt_stats(rtt_dict, src_packets[0].ipv4.src_ip,intermediate_nodes)

#print(analyze_ttl(src_packets))
