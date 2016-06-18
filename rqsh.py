#!/usr/bin/python2

import threading
import argparse
import socket
import sys
import os
import netifaces
from receiver import receiver
from sender import sender

def main():
	parser = argparse.ArgumentParser(
		description = 'rqsh send and receive untility tool')

	#------------Main Args------------------
	parser.add_argument('-q', nargs = '+', help = 'quickly send a command and wait for result -> Unreliable')
	parser.add_argument('-s', nargs = '+', help = 'send data, do not wait for response')
	parser.add_argument('-l', action = 'store_true', help = 'run in listen mode, dump incoming data to cmd')
	parser.add_argument('-x', action = 'store_true', help = 'run in execute mode, ')
	parser.add_argument('-i', nargs='?', help="network interface, REQUIRED")

	#-------------Debugging Args-----------------------
	parser.add_argument('-d', help="debug mode", action='store_true')
	parser.add_argument('-p', nargs = '?', type = int, help = 'define non-default port #', default = 5005)
	parser.add_argument('-m', nargs = '?', type = str, help = 'define multicast group address', default = "224.3.29.71")
	#TODO self test mode

	#--------------File Transfer Args------------------
	parser.add_argument('-g', nargs='+', help = 'get a file from a destination running -x mode',
		metavar = 'address:file [local_dest]')

	parser.add_argument('-t', nargs='+', help = 'transmit (send) a file to a destination running -x mode',
		metavar = 'local_file address[:dest]')

	#--------tuning/performance args----------
	parser.add_argument('-lr', nargs = 1, type = float,
		default = 0.0, help = 'expected lose rate, will calculate the N for encoder')

	#--------------Main-----------------------
	args = None
	args = parser.parse_args(sys.argv[1:] if args is None else args)

	interfaces = netifaces.interfaces()
	my_ip = None
	for i in interfaces:
		if i == args.i:
			my_ip = netifaces.ifaddresses(i).get(netifaces.AF_INET)[0]['addr']
	if args.d:
		print my_ip
	if my_ip == None:
		print 'invalid network interface'
		exit(1)

	sndr = sender(loss = args.lr, mc_group = args.m, port = args.p, debug = args.d, ip=my_ip)

	#----------------decision tree---------------
	data_header = 0
	host_ip = None
	host_file  = None
	local_file = None
	#Data header types
	#0 = plaintext dump/command response
	#1 = command
	#2 = request file
	#3 = file dump/file response

	if args.q: #quicksend single command
		data_header = 1
		recv = receiver(port = args.p, exe = False, mc_group = args.m, debug = args.d)
		recv.blacklist(my_ip)
		t_id = threading.Thread(target = recv.start, kwargs = {'max_messages':1})
		t_id.daemon = True
		t_id.start()

	elif args.l: #launch daemon in listen mode
		recv = receiver(port = args.p, exe = False, mc_group = args.m, debug = args.d)
		recv.start(max_messages = -1)
	
	elif args.x: #launch daemon in exe mode
		recv = receiver(port = args.p, exe = True, mc_group = args.m, debug = args.d, sndr=sndr)
		recv.blacklist(my_ip)
		recv.start(max_messages = -1)

	elif args.g: #get file
		#TODO open quicksend style listener
		#also TODO build a file only mode
		data_header = 2
		if len(args.g) < 1:
			print 'give arguments to -g please!'
			exit(1)
		try:
			host_ip = args.g[0].split(':')[0]
			host_file = args.g[0].split(':')[1]
			if len(args) > 1:
				local_file = args.g[1]
			else:
				local_file = os.path.join(os.getcwd(), os.path.split(host_file)[1])
		except:
			print 'invalid syntax to -g'
			exit(1)

	elif args.t: #transmit file
		data_header = 3
		if len(args.t) < 1:
			print 'give arguments to -t please!'
			exit(1)
		try:
			local_file = args.t[0]
			host_ip = args.t[1].split(':')[0]
			if len(args.t[1].split(':')) > 1:
				host_file = argt.g[1].split(':')[1]
			else:
				os.path.split(local_file)[1]
		except:
			print 'invalid syntax to -t'
			exit(1)
	
	if args.q or args.s or args.g or args.t:
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
	
		#this front-end only needs to deal with 'sending' types, 1,2,3
		data = str(data_header) + delim

		#TODO find a better delimeter
		delim = '#' #delimiter for rqsh syntax 

		if data_header == 2:
			data += host_ip + delim + host_file + delim + local_file
		
		elif data_header == 3:
			file = open(local_file, 'r')
			payload = file.read()
			file.close()
		
			data += host_file + delim + payload_size + delim + payload

		elif data_header == 1:
			try: 
				for i in args.q:
					data += i + ' '
			except: pass

			try:
				for j in args.s:
					data += j + ' '
			except: pass

	sndr.send(data[:-1])
	
	if args.q:
		input() #wait for all threads to finish

main()
