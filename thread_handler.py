import time
import json
import threading
import math
import os
import libraptorq
import base64
from libraptorq import RQEncoder, RQDecoder, RQError

#from subprocess import Popen, PIPE, STDOUT

from readwritelock import ReadWriteLock

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
        base64.urlsafe_b64decode(bytes(s))\
                if '-' in s or '_' in s else bytes(s).decode('base64')


# thread handler will be a class that groups the symbols and then attempts to decode them
class thread_handler:
        class thread_data:
                def __init__(self, o_common, o_scheme, addr, lst, lock, t):
			self.address = addr
			self.oti_common = o_common
			self.oti_scheme = o_scheme
                        self.data = lst
                        self.rw_lock = lock
			self.u_clock = t

        def __init__(self):
                self.threads = {}
                self.rw_lock = ReadWriteLock()
                self.timeout_interval = 5.0 #time in seconds to kill thread if no new data has been recieved
		self.update_interval = 0.2 #update interval (secs) should be tuned to the expected number of simultaneous conncetions, higher = better performance with more users, lower = better with less
		self.debug_mode = False

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

                else: #otherwise we need to figure out which thread is working on this block and add this to it's data list
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
		#p = Popen(['rq', 'decode'], stdin=PIPE)
		#p.communicate(input=json.dumps(dic,sort_keys=True, indent=2, separators=(',', ': ')))
		
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
		#p.poll()
		if self.debug_mode:
			if succ:
				print "successfully decodeded"
				print data
			else:
				print "failed to decode"
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

