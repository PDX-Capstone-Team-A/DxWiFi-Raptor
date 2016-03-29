import time
import json
import threading
import math
import os
from subprocess import Popen, PIPE, STDOUT

import readwritelock

# thread handler will be a class that groups the symbols and then attempts to decode them
class thread_handler:
        class thread_data:
                def __init__(tid, lst, lock):
                        thread_id = tid
                        data = lst
                        rw_lock = lock

        def __init__():
                threads = {}
                rw_lock = ReadWriteLock()
                timeout_inverval = 2.0 #time in seconds to kill thread if no new data has been recieved
		update_interval = 0.01 #update interval (secs) should be tuned to the expected number of simultaneous conncetions, higher = better performance with more users, lower = better with less

        def add_item(address, oti_common, oti_scheme, sym_id, sym):
                rw_lock.acquire_read()
                #if we have no value for this key then it is the first for its data block
                #create a new thread for it and add the first symbols
                if ! threads [(address, oti_common, oti_scheme)]:
                        rw_lock.release_read()
                        rw_lock.acquire_write()

                        #create thread item
                        lock = ReadWriteLock()
                        data = [[sym_id, sym)]]

                        #fork thread
                        t_id = threading.Thread(target = worker, args = (oti_common, oti_scheme, data, lock))
                        thread_item = threads (t_id, data, lock)
			t_id.start()

                        #add thread to dict, hash key is the 3tuple (addr, common, scheme)
                        threads [(address, oti_common, oti_scheme)] = thread_item

                        rw_lock.release_write()
                else: #otherwise we need to figure out which thread is working on this block and add this to it's data list
		   	rw_lock.release_read()
                        thread_item = threads [(address, oti_common, oti_scheme)]
                        thread_item.rw_lock.acquire_write()
                        thread_item.data.append([sym_id, sym])
                        thread_item.rw_lock.release_write()


        def worker(oti_common, oti_scheme, data, lock):
                timer = time.clock()

                #extract the variables accorinding to the notes.txt file
                size =  0xFFFFFFFFFF| (oti_common >> 24) ###need to make sure that these arnt being cast down to 32 bit integers or we will lose critical data
                symbol_size = 0xFFFF | oti_common
                total_symbols = math.ceil(size/symbol_size)

                required_symbols = math.ceil (1.1*total_symbols) #the paper said we need .02% exccess packets but we'll use this for now just to be safe
		while time.clock() - timer < timeout_interval:
			lock.acquire_read()
			if len(data) >= required_symbols:
				lock.release_read()
				process_data(oti_common, oti_scheme, data, lock)
				break
			lock.release_read()
			time.sleep(update_interval)
			timer = time.clock()
		
		###cleanup routine
		rw_lock.acquire_write()
		del threads[(address, oti_common, oti_scheme)]
		rw_lock.release_write()
			
	
	def process_data(oti_common, oti_scheme, data, lock):
		#what this does will depend largly on the data, as it currently stands i plan on making this routine call rq decode on the data and printing  it to stdout
		lock.acquire_read()
		dic = {}
		dic['data_bytes'] = 0xFFFFFFFFFF| (oti_common >> 24) ###need to make sure that these arnt being cast down to 32 bit integers or we will lose critical data
		dic['oti_common'] = oti_common
		dic['oti_scheme'] = oti_scheme
		dic['symbols'] = data
		p = Popen(['rq', 'decode'], stdin=PIPE)
		p.communicate(input=json.dumps(dic,sort_keys=True, indent=2, separators=(',', ': ')))






