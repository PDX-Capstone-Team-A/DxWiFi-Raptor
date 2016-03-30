#!/usr/bin/python2
import json
import argparse
import sys
import random
import math

# script to drop a percentage of symbols from the json file- to help test performance of raptor codes


args=None
parser = argparse.ArgumentParser(description= 'drop random data from the json file')
parser.add_argument('-p', nargs='?', help="drop a percentage of data")
parser.add_argument('-n', nargs='?', help="drop n data packets")
args = parser.parse_args(sys.argv[1:] if args is None else args)



infile =  sys.stdin
data = json.loads(infile.read()) #load the data from the libraptor rq command
oti_common = data['oti_common']
oti_scheme = data['oti_scheme']

syms = data['symbols']
random.shuffle(syms)

n = 0
if (args.p):
	rate = float(args.p)/100.0
	n = int(math.ceil(rate * len(syms)))
elif (args.n):
	n = int(args.n)

syms = syms[n:]
data['symbols'] = syms

#sys.stdout.write(json.dumps(data,sort_keys=True, indent=2, separators=(',', ': ')))
print(json.dumps(data,sort_keys=True, indent=2, separators=(',', ': ')))

