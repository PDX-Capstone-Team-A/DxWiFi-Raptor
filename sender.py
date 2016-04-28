import socket, struct, time, json, base64, sys, types, math
from libraptorq import RQEncoder

b64_encode = base64.urlsafe_b64encode
b64_decode = lambda s:\
        base64.urlsafe_b64decode(bytes(s))\
                if '-' in s or '_' in s else bytes(s).decode('base64')

class Sender:
    """ Sender - Our sending object, will collect parse and send out information
    on the desired socket """

    def __init__(self, loss = 0.0, mc_group = '224.3.29.71', port = 5005, debug = False):
        
        self.loss = loss
        self.io_ratio = 1.0 + loss / (1.0 - loss)
		self.multicast_group = (mc_group, port)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.settimeout(100)
		ttl = struct.pack('b', 1)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

		self.min_subsymbol_size = 8  #using rqencoder defaults for now... change later?
    	self.symbol_size = 16
    	self.max_memory = 200
    	self.threads = 0
    	self.debug = debug

    def send(self, data):

       data_len = len(data)
       if data_len % 4: data += '\0' * (4 - data_len % 4)
       with RQEncoder( data,
                       self.min_subsymbol_size, self.symbol_size, self.max_memory ) as enc:
               oti_scheme, oti_common = enc.oti_scheme, enc.oti_common
               enc.precompute(self.threads, background=False)                        
               symbols, enc_k, n_drop = list(), 0, 0
               for block in enc:
                       enc_k += block.symbols # not including repair ones
                       block_syms = list(block.encode_iter(
                               repair_rate=self.io_ratio))
                       symbols.extend(block_syms)                
                       symbols = filter(None, symbols)
       data = dict( data_bytes=data_len,
                       oti_scheme=oti_scheme, oti_common=oti_common,
                       symbols=list((s[0], b64_encode(s[1])) for s in symbols)) 

		oti_common = int(data['oti_common'])
		oti_scheme = int(data['oti_scheme'])
		
		for sym_id, sym in data['symbols']:
			datastring = struct.pack('!QQQ24s', oti_common, oti_scheme, int(sym_id), sym.encode('ascii','ignore'))
			###TODO: base64 encodings waste 3 bits of entropy per byte. binary encoding scheme will be better but we need to be sure that the socket library supports non-ascii data transfer
			# print(datastring)
			# print (b64_decode(sym))
			self.sock.sendto(datastring, multicast_group)

		print 'Sent ' + str(len(data['symbols'])) + ' packets'
	