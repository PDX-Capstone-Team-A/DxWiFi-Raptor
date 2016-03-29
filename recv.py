import time
import socket
import struct
import sys
import json
import base64
import threading
import math

import readwritelock

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
        base64.urlsafe_b64decode(bytes(s))\
                if '-' in s or '_' in s else bytes(s).decode('base64')

# thread handler will be a class that groups the symbols and then attempts to decode them
# this should probly be moved to another file at some point
class thread_handler:
	class thread_data:
		def __init__(tid, lst, lock):
			thread_id = tid
			data = lst
			rw_lock = lock
			
	def __initi__():
		threads = {}
		rw_lock = ReadWriteLock()

	def add_item(address, oti_common, oti_scheme, sym_id, sym):
		rw_lock.acquire_read()
		#if we have no value for this key then it is the first for its data block
		#create a new thread for it and add the first symbols
		if ! threads [(address, oti_common, oti_scheme)]:
			rw_lock.release_read()
			rw_lock.acquire_write()

			#create thread item
			lock = ReadWriteLock()
			data = [(sym_id, sym)]
	
			#fork thread
			t_id = threading.Thread(target = worker, args = (oti_common, oti_scheme, data, lock))
			thread_item = threads (t_id, data, lock)

			#add thread to dict, hash key is the 3tuple (addr, common, scheme)
			threads [(address, oti_common, oti_scheme)] = thread_item

			rw_lock.release_write()
		else: #otherwise we need to figure out which thread is working on this block and add this to it's data list
			rw_lock.release_read()
			thread_item = threads [(address, oti_common, oti_scheme)]
			thread_item.rw_lock.acquire_write()
			thread_item.data.append((sym_id, sym))
			thread_item.rw_lock.release_write()


	def worker(oti_common, oti_scheme, data, lock):
		required symbols = math.ceil (1.1*total_symbols) #the paper said we need .02% exccess packets but we'll use this for now just to be safe
		timeout_inverval = 2.0 #time in seconds to kill thread if no new data has been recieved
		timer = time.clock()

		#extract the variables accorinding to the notes.txt file
		size =  0xFFFFFFFFFF| (oti_common >> 24) ###need to make sure that these arnt being cast down to 32 bit integers or we will lose critical data
		symbol_size = 0xFFFF | oti_common
		total_symbols = math.ceil(size/symbol_size)


		

		
		






	
		

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
	group = socket.inet_aton(multicast_group)
	mreq = struct.pack('4sL', group, socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

	while True:
		data, address = sock.recvfrom(1024)
		oti_common, oti_scheme, sym_id, sym = struct.unpack('!iii24s', data)
		thread_handler.add_item(address, oti_common, oti_scheme, sym_id, sym)


main()
	
