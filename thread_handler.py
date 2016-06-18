import time
import pipes
import json
import threading
import math
import os
import libraptorq
import base64
from libraptorq import RQEncoder, RQDecoder, RQError

from subprocess import Popen, PIPE, STDOUT

from readwritelock import ReadWriteLock

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
		base64.urlsafe_b64decode(bytes(s))\
			if '-' in s or '_' in s else bytes(s).decode('base64')


# thread handler will be a class that groups the symbols and then attempts to decode them
class thread_handler:
	class thread_data:
		def __init__(self, o_common, o_scheme, addr, lst, lock, t, exe=False):
			self.address = addr
			self.oti_common = o_common
			self.oti_scheme = o_scheme
			self.data = lst
			self.rw_lock = lock
			self.u_clock = t
			self.no_exec = exe
			self.zombie = False
			

	def __init__(self, max_messages, exe = False, sndr=None, delim='#'):
		self.sender_obj = sndr
		self.exe = exe
		self.max_messages = max_messages
		self.num_messages = 0
		self.threads = {}
		self.rw_lock = ReadWriteLock()
		self.timeout_interval = 5.0 #time in seconds to kill thread if no new data has been recieved
		self.update_interval = 0.2 #update interval (secs) should be tuned to the expected number of simultaneous conncetions, higher = better performance with more users, lower = better with less
		self.debug_mode = False
		self.delim = delim

	def add_item(self, address, oti_common, oti_scheme, sym_id, sym):
		if self.debug_mode:
			print "adding new item"
			self.rw_lock.acquire_read()
			#if we have no value for this key then it is the first for its data block
			#create a new thread for it and add the first symbols
		if not (address, oti_common, oti_scheme) in self.threads:
			self.rw_lock.release_read()

			#create thread item
			lock = ReadWriteLock()
			data = [[sym_id, sym]]
			u_clock = time.time()

			#fork thread
			thread_item = self.thread_data(oti_common, oti_scheme, address, data, lock, u_clock)
			t_id = threading.Thread(target = self.worker, args = (thread_item,))
			t_id.daemon = True

			#add thread data to dict, hash key is the 3tuple (addr, common, scheme)
			self.rw_lock.acquire_write()
			self.threads [(address, oti_common, oti_scheme)] = thread_item
			self.rw_lock.release_write()

			t_id.start()

		elif not self.threads[(address, oti_common, oti_scheme)].zombie : #otherwise we need to figure out which thread is working on this block and add this to it's data list
			thread_item = self.threads [(address, oti_common, oti_scheme)]
			self.rw_lock.release_read()
			thread_item.rw_lock.acquire_write()
			thread_item.data.append([sym_id, sym])
			thread_item.u_clock = time.time()
			thread_item.rw_lock.release_write()


	def worker(self, thread_data):
		#extract the variables accorinding to the notes.txt file
		size =  0xFFFFFFFF & (thread_data.oti_common >> 24) ###need to make sure that these arnt being cast down to 32 bit integers or we will lose critical data
		symbol_size = 0xFFFF & thread_data.oti_common
		total_symbols = math.ceil (size / symbol_size)

		min_required_symbols = math.ceil (1.2*total_symbols) #the paper said we need .02% exccess packets but we'll use this for now just to be safe
		max_symbols = 3 * total_symbols

		if self.debug_mode:
			print "creating new thread"
			print "size = " + str(size)
			print "symbol size = " + str(symbol_size)
			print "total_symbols = " + str(total_symbols)
			print "this thread needs at least " + str(min_required_symbols) + " symbols"
			print "thread max symbols = " + str(max_symbols)
	
		thread_data.rw_lock.acquire_read()
		while time.time() - thread_data.u_clock < self.timeout_interval:
			self.rw_lock.acquire_read()
			if self.num_messages >= self.max_messages and self.max_messages >= 0: #break if max messages excited
				break
			self.rw_lock.release_read()

			if self.debug_mode:
				print "thread update clock = " + str(thread_data.u_clock)
				print "actual clock = " + str(time.time())
			if len(thread_data.data) >= min_required_symbols:
				thread_data.rw_lock.release_read()
				succ = self.process_data(thread_data)
				thread_data.rw_lock.acquire_read()
				if not succ:
					thread_data.rw_lock.release_read()
					time.sleep(self.update_interval)
					thread_data.rw_lock.acquire_read()
					continue
				self.rw_lock.acquire_write()
				self.num_messages += 1 
				thread_data.zombie = True
				self.rw_lock.release_write()
				break
			thread_data.rw_lock.release_read()
			time.sleep(self.update_interval)
			thread_data.rw_lock.acquire_read()
		

			#thread_data.rw_lock.acquire_write()
			#thread_data.u_clock = time.time()
			#thread_data.rw_lock.release_write()
		thread_data.rw_lock.release_read()
	
		###cleanup routine
		print "exiting worker thread"
		time.sleep(self.update_interval)
		self.rw_lock.acquire_write()
		del self.threads[(thread_data.address, thread_data.oti_common, thread_data.oti_scheme)]
		self.rw_lock.release_write()
			
	
	def process_data(self, thread_data):
		#what this does will depend largly on the data, as it currently stands i plan on making this routine call rq decode on the data and printing  it to stdout
		thread_data.rw_lock.acquire_read()
		data = {}
		data['data_bytes'] = 0xFFFFFFFFFF & (thread_data.oti_common >> 24) ###need to make sure that these arnt being cast down to 32 bit integers or we will lose critical data
		data['oti_common'] = thread_data.oti_common
		data['oti_scheme'] = thread_data.oti_scheme
		data['symbols'] = thread_data.data
		if self.debug_mode:
			print "sending over " + str(len(thread_data.data)) + " symbols for decoding"
			print "printing data and forking rq"
			
		n_syms, n_syms_total, n_sym_bytes = 0, len(data['symbols']), 0
		data_len = data['data_bytes']
		succ = False

		with RQDecoder(data['oti_common'], data['oti_scheme']) as dec:
			err = 'no symbols available'
			for sym_id, sym in data['symbols']:
				sym_id, sym = int(sym_id), b64_decode(sym)
				
				try: dec.add_symbol(sym, sym_id)
				except Exception as err: continue
				
				n_syms, n_sym_bytes = n_syms + 1, n_sym_bytes + len(sym)
				
				try: data = dec.decode()[:data_len]
				except RQError as err: pass
				else:
					succ = True
					break
			else:
				if self.debug_mode:
					print 'Faled to decode data from ' + str(n_syms_total) + ' symbols'

		thread_data.rw_lock.release_read()
		if not succ:
			return False
		if self.debug_mode:
		 	if succ:
		 		print "successfully decodeded"
		 		print data
		 	else:
		 		print "failed to decode"

		stdout_data = ''

		#Parse command type according to:

        #Data header types
        #0 = plaintext dump/command response
        #1 = command
        #2 = request file
        #3 = file dump/file response

        #data header syntax
        # 0: [header (this number)]\d[text size]\d[text]
        # 1: [header]\d[command]
        # 2: [header]\d[host_ip]\d[host_file]\d[local_file]
        # 3: [header]\d[dest_file aka host_file]\d[payload_size]\d[payload]

		header = data.split(self.delim)[0]
		#Note, these files are reverse because WE are the server
		host_file = None #our file
		local_file = None #local to the requester
		payload = None
		size = None #payload or text sizei
		host_ip = None #our ip?
		text = None

		if header == '0':
			size = int (data.split(self.delim)[1])
			text = data[:-size] #dont use split in case payload uses the delimiter for whatever reason
			
		elif header == '1':
			text = data.split(self.delim)[1]
			
		elif header == '2':
			host_ip = data.split(self.delim)[1]
			host_file = data.split(self.delim)[2]
			local_file = data.split(self.delim)[3]
			
		elif header == '3':
			host_file = data.split(self.delim)[1]
			size = int (data.split(self.delim)[2])
			payload = data[:-size] #dont use split in case payload uses the delimiter for whatever reason

		#TODO figure out what to do with these variables. all the code below this point is for an older protocol and will not work. must fix 
		
		
		if self.exe:
			if header == '0':
				print text
			elif header == '1':
				#run command
				cmd = text.split('\n', 1)[0]
				cmd = str(cmd).strip('\0').strip().split()
				if self.debug_mode:
					print ":".join("{:02x}".format(ord(c)) for c in cmd)
				try: stdin_data = text.split('\n', 1)[1]
				except: stdin_data = ''
				if self.exe:
					p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE)
					stdout_data, stderr_data = p.communicate(stdin_data)
					p.wait()
					return_code = p.returncode
					if self.debug_mode:
						print stdout_data
				else:
					if self.debug_mode:
						print cmd
						print stdin_data
				response = '0' + self.delim + stdout_data
				sender_obj.send(response)
			
			elif header == '2' and host_ip == sender_obj.my_ip:
				#[header]\d[dest_file aka host_file]\d[payload_size]\d[payload]
				try:
					f = open(host_file)
					to_send_data = f.read()
					send_str = '3' + self.delim + local_file + self.delim + str(len(to_send_data)) +
						self.delim + to_send_data
					sender_obj.send(send_str)
					f.close()
				except:
					send_str = '0' + self.delim + 'error, unable to open file: ' + host_file
					sender_obj.send(send_str)
			
			elif header == '3':
				try:
					f = open(host_file, 'w')#not really host file
					f.write(payload)
					f.close()
				except:
					print 'error, unable to open local file: ' + host_file

		else:
				print data

		if self.debug_mode:
			print 'header = ' + header
			print 'host file =' + host_file
			print 'local file = ' + local_file
			print 'size = ' + size
			print 'host ip = ' + host_ip
			print 'text = ' + text
			if payload:
				print 'payload exists'
			else:
				print 'payload is null'

		if self.sender_obj:
			if self.debug_mode:
				print 'sending data'
		return succ

	def unit_test(self, infile):
		data = json.loads(infile.read())
		infile.close()
		oti_common = data['oti_common']
		oti_scheme = data['oti_scheme']
		for sym_id, sym in data['symbols']:
			self.add_item("127.0.0.1", oti_common, oti_scheme, sym_id, sym)



#t_handler = thread_handler()
#t_handler.debug_mode = True
#f = open('testdata.json', 'r')
#t_handler.unit_test(f)

