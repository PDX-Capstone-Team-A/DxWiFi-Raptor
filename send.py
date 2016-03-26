import time
import socket
import struct
import sys
import json
import base64

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
        base64.urlsafe_b64decode(bytes(s))\
                if '-' in s or '_' in s else bytes(s).decode('base64')


message = 'very important data'
multicast_group = ('224.3.29.71', 10000)

# Create the datagram socket
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set a timeout so the socket does not block indefinitely when trying
# to receive data.
#sock.settimeout(100)

# Set the time-to-live for messages to 1 so they do not go past the
# local network segment.
#ttl = struct.pack('b', 1)
#sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

def main(args=None, error_func=None):
	import argparse

	parser = argparse.ArgumentParser(
                description= 'send code via udp multicast')
        parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	parser.add_argument('-i', nargs='?', help="input file (json format)")

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

 	src = sys.stdin
        try: data = src.read()
        finally: src.close()

	data = json.loads(data)
	n_syms, n_syms_total, n_sym_bytes = 0, len(data['symbols']), 0
        data_len = data['data_bytes']

	print("starting stuff")
	for sym_id, sym in data['symbols']:
		datastring = struct.pack('!i24s', sym_id, sym.encode('ascii','ignore'))
		print(datastring)
		#sock.sendto(data_string, multicast_group)

	

main()
	
