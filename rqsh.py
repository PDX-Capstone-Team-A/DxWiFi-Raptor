#!/usr/bin/python2

import argparse
import socket
import sys
from receiver import receiver
from sender import sender

def main():
	parser = argparse.ArgumentParser(
		description = 'rqsh send and receive untility tool')
	parser.add_argument('-q', nargs = '+', help = 'quickly send a command and wait for result -> Unreliable')
	parser.add_argument('-s', nargs = '+', help = 'send data, do not wait for response')
	parser.add_argument('-l', action = 'store_true', help = 'run in listen mode, dump incoming data to cmd')
	parser.add_argument('-x', action = 'store_true', help = 'run in execute mode, ')
	parser.add_argument('-p', nargs = 1, type = int, help = 'define non-default port #', default = 5005)
	parser.add_argument('-m', nargs = 1, type = str, help = 'define multicast group address', default = "224.3.29.71")
	parser.add_argument('-d', help="debug mode", action='store_true')

	parser.add_argument('-lr', nargs = 1, type = float,
		default = 0.0, help = 'expected lose rate, will calculate the N for encoder')
	args = None
	args = parser.parse_args(sys.argv[1:] if args is None else args)

	sndr = sender(loss = args.lr, mc_group = args.m, port = args.p, debug = args.d)

	if args.q:
		recv = receiver(port = args.p, exe = False, mc_group = args.m, debug = args.d)
		recv.blacklist(socket.gethostbyname(socket.gethostname()))
		t_id = threading.Thread(target = recv.start, kwargs = {'max_messages':1})
		t_id.daemon = True
		t_id.start()

	elif args.l:
		recv = receiver(port = args.p, exe = False, mc_group = args.m, debug = args.d)
		recv.start(max_messages = -1)
	
	elif args.x:
		recv = receiver(port = args.p, exe = True, mc_group = args.m, debug = args.d, sender=sndr)
		recv.start(max_messages = -1)
	
	if args.q or args.s:
		data = ""

		try: 
			for i in args.q:
				data += i + ' '
		except: pass

		try:
			for j in args.s:
				data += j + ' '
		except: pass


		sndr.send(data[:-1])

main()
