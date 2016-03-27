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

def main(args=None, error_func=None):
	import argparse

	parser = argparse.ArgumentParser(
                description= 'send code via udp multicast')
	parser.add_argument('-i', nargs='?', help="input file (json format)")
	parser.add_argument('-p', nargs='?', type=int, default=5005, help="port to send to, default = 5005")
	parser.add_argument('-d', nargs='?', default ="224.3.29.71", help="destination to send to, default = 224.3.29.71")

	args = parser.parse_args(sys.argv[1:] if args is None else args)

	multicast_group = (args.d, args.p)

	# Create the datagram socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Set a timeout so the socket does not block indefinitely when trying
	# to receive data.
	sock.settimeout(100)

	# Set the time-to-live for messages to 1 so they do not go past the
	# local network segment.
	ttl = struct.pack('b', 1)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)


	if args.i:
		src = open(args.i, 'r')
	else:
 		src = sys.stdin

        try: data = src.read()
        finally: src.close()

	data = json.loads(data) #load the data from the libraptor rq command
	oti_common = int(data['oti_common'])
	oti_scheme = int(data['oti_scheme'])

	for sym_id, sym in data['symbols']:
		datastring = struct.pack('!iii24s', oti_common, oti_scheme, sym_id, sym.encode('ascii','ignore'))
		###TODO: base64 encodings waste 3 bits of entropy per byte. binary encoding scheme will be better but we need to be sure that the socket library supports non-ascii data transfer
		print(datastring)
		print (b64_decode(sym))
		#sock.sendto(data_string, multicast_group)

	

main()
	
