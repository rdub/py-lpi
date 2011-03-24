#!/usr/bin/env python

import sys
from pprint import pprint
from struct import *
import string

def chip_string(sequence, string):
	
	stream = []
	jj = 0
	while jj < len(string):
		byte = (unpack('b', string[jj]))[0]
		ii = 1
		while ii <= 128:
			bit = 1
			if(not (byte & ii)):
				# bit is a 0, transmutate into a -1
				bit = -1
			
			# multiply by the sequence
			symbol = map(lambda x:bit*x, sequence)
			stream.extend(symbol)
						
			ii <<= 1
		
		jj += 1
	return stream

def stream_bit_to_bit(bit):
	if(bit > 0):
		return 1
	return 0

def stream_to_string(stream):
	ii = 0
	accum = 0
	string = ""
	while ii < len(stream):
		if(not (ii % 8) and ii):
			# emit the byte
			string += pack('B', accum)
			#print "0x%x" % accum
			accum = 0
			
		accum |= stream_bit_to_bit(stream[ii]) << (ii % 8)
		ii += 1
	return string
	
# basically, dot product code
def dechip_bit(sequence, symbol):
	# symbol and sequence are assumed to be the same length
	ii = 0
	product = 0
	while ii < len(sequence):
		product += sequence[ii]*symbol[ii]
		ii += 1
		
	if(product > 0):
		return 1
	return 0
	
def dechip_byte(sequence, stream):
	seq_len = len(sequence)
	match = "%s%s -_" % (string.ascii_letters, string.digits)
	# break the stream into chunks the same length as the sequence used
	str_len = len(stream)
	
	ii = 0
	byte = 0
	while ii < 8:
		bit_stream = stream[(ii*seq_len):((ii*seq_len)+seq_len)]
		bit = dechip_bit(sequence, bit_stream)
		
		byte |= (bit << ii)
		
		ii += 1
	
	if(pack('B',byte) in match):
		return byte
	return None
	
def dechip_stream(sequence, stream):
	# can only decode in modulo sequence length
	sequence_len = len(sequence)
	bytes = int(len(stream)/sequence_len)/8
	
	string = ""
	
	#print "decoding at most %d bytes" % bytes
	
	while string == "" and len(stream):
		ii = 0
		while ii < bytes:
		
			start = (ii*sequence_len*8)
			end = start + (sequence_len*8)
		
			#print " looking at bits %d to %d" % (start, end)
		
			byte = dechip_byte(sequence, stream[(ii*sequence_len*8):((ii*sequence_len*8) + (sequence_len*8))])
			if(byte == None):
				#shift the stream over if we miss
				stream = stream[1:]
				string = ""
				break
		
			#print "0x%x" % byte
		
			b_str = pack("B", byte)
		
			#print b_str
		
			string += b_str
		
			ii += 1
	
		
	return string
	

def chip_table(len, seed):
	ret = []
	
	if(2 == len):
		return [[seed, seed],[seed,-1*seed]]
		
	sub = chip_table(len/2, seed)
		
	additions = []
	
	for half in sub:
		addition = []
		addition.extend(half)
		addition.extend(half)
		additions.append(addition)
		
		addition = []
		addition.extend(half)
		addition.extend(map(lambda x:-1*x, half))
		additions.append(addition)
	
	return additions


def main():
	length = int(sys.argv[1])
	key = int(sys.argv[2])
	
	# make it even
	if(length % 2):
		length += 1
		
	if(key >= length):
		print "Key must be less than chip table size"
		
	
	table = chip_table(length, 1)
	
	seq = table[key]
	
	# test interference string
	seq2 = table[(key + 2) % length]
	
	#print "using sequence:"
	#pprint(seq)
	
	stream = chip_string(seq, "the quick brown fox")
	
	int_stream = chip_string(seq2, "your mom is a whore")
	
	
	print "the quick brown fox (%d bit stream):" % (len(stream))
	#pprint(stream)
	
	summed = map(lambda x,y: x+y, stream, int_stream)
	
	bytes = stream_to_string(summed) #stream_to_string(stream)
	ii = 0
	while ii < len(bytes):
		sys.stdout.write("\\x%02x" % int(unpack('B',bytes[ii])[0]))
		ii += 1
	print ""
	
	print "dechipping:"
	
	ii = 0
	while ii < len(summed) - 64:
		
		string = dechip_stream(seq, summed[ii:])
		if(string != None):
			print "off: %d bits: string: %s" % (ii, string)
		
		string = dechip_stream(seq2, summed[ii:])
		if(string != None):
			print "off: %d bits: string2: %s" % (ii, string)
		
		ii += 1
	
	sys.exit(0)

	


if __name__ == "__main__":
    main()