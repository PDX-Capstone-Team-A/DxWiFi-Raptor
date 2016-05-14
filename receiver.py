import socket, sys, struct
from thread_handler import thread_handler

class receiver:
	""" Receiver - Our Receiver object will do two things
	1. It will listen for incoming commands on the specified node
	2. Execute or deny commands that are received """

	def __init__(self,  port = 5005, exe = False, mc_group = "224.3.29.71", debug = False, sndr=None):
		self.blist = []
		self.exe = exe
		self.mc_group = (str(mc_group), port)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind(self.mc_group)
		group = socket.inet_aton(mc_group)
		mreq = struct.pack('4sL', group, socket.INADDR_ANY)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
		self.debug = debug
		
		self.sender_obj = sndr

	def start(self, max_messages = -1):

		handler = thread_handler(max_messages, exe = self.exe, sndr=self.sender_obj)

		handler.debug_mode = self.debug

		while True:
			data, address = self.sock.recvfrom(1024)
			oti_common, oti_scheme, sym_id, sym = struct.unpack('!QQQ24s', data)
			if not address[0] in self.blist:
				if self.debug:
					print "oti_common = " + str(oti_common)
					print "oti_scheme = " + str(oti_scheme)
					print "sym_id = " + str(sym_id)
					print "sym = " + str(sym)
					print address
					print str(self.blist)
				handler.add_item(address, oti_common, oti_scheme, sym_id, sym)    	

	def blacklist(self, ip):
		self.blist.append(ip)
