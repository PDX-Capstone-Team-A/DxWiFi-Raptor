#!/usr/bin/python2
import time
import socket
import struct
import sys
import json
import base64
import threading
import math

import readwritelock
from thread_handler import thread_handler

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
        base64.urlsafe_b64decode(bytes(s))\
                if '-' in s or '_' in s else bytes(s).decode('base64')
	

debug = True
def main(args=None, error_func=None):
	import argparse

	parser = argparse.ArgumentParser(
                description= 'send code via udp multicast')
	parser.add_argument('-o', nargs='?', help="output file (json format)")
	parser.add_argument('-p', nargs='?', type=int, default=5005, help="port to send to, default = 5005")
	parser.add_argument('-g', nargs='?', default ="224.3.29.71", help="multicast group address, default = 224.3.29.71")

	args = parser.parse_args(sys.argv[1:] if args is None else args)

	multicast_group = (args.g, args.p)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(multicast_group)
	group = socket.inet_aton(multicast_group[0])
	mreq = struct.pack('4sL', group, socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

	#initialize a thread_handler object
	handler = thread_handler()
	#handler.debug_mode = True

	while True:
		data, address = sock.recvfrom(1024)
		oti_common, oti_scheme, sym_id, sym = struct.unpack('!QQQ24s', data)
		#if debug:
			#print "oti_common = " + str(oti_common)
			#print "oti_scheme = " + str(oti_scheme)
			#print "sym_id = " + str(sym_id)
			#print "sym = " + str(sym)

		handler.add_item(address, oti_common, oti_scheme, sym_id, sym)


main()
	
