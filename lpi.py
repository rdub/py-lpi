#!/usr/bin/env python

import sys
from pprint import pprint
from struct import *
import string
import hashlib

# Encoded as bytes in the header
VERSION_MAJOR=1
VERSION_MINOR=0
VERSION_REVISION=0

# Encoded as network-order long
LPI_MAGIC=0xbeef1234

def chip_bytes(sequence, data_stream):
	'''
	chip_bytes(sequence, data_stream):
		Encodes a given byte stream (should be a list of bytes) with the given chipping sequence.
		resulting data will be a list of bits. This will *expand* your input stream by len(sequence) bits per bit
		If len(data_stream) is 8, and len(sequence) is 4, then the resulting data size will be 
		8 (number of bytes) * 8 (8 bits per byte) * 4 (bit-length of chipping sequence).
		Resulting data will be a stream of +1 or -1.  When encoding this data, anyvalue <= 0 should be encoded as a 0.
		
		It is possible to sum to data streams into the same sequence. Simply encoded both with 2 orthogonal chipping
		sequences, add the resulting bit-vectors. 
	
	sequence:
		Chipping sequence (bit-vector). Should be orthogonal to any other bit-vector possibly used.
		
	data_stream:
		list of bytes (unsigned char) values to encode.
		
	return value:
		bit-stream (not byte-stream) of encoded data
	'''
	
	# ToDo
	
	bit_stream = []
	
	dlen = len(data_stream)
	ii = 0
	while ii < dlen:
		jj = 0
		while jj < 8:
			if(data_stream[ii] & (1 << jj)):
				bit_stream.extend(sequence)
			else:
				bit_stream.extend(map(lambda x:-1*x, sequence))
			jj += 1
		ii += 1
	
	return bit_stream

def chip_header(sequence):
	string = "\x01" + pack("!BBBL", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, LPI_MAGIC)
	stream = __chip_string(sequence, string)
	
	return stream
	
def dechip_header(sequence, stream):
	string = __dechip_stream(sequence, stream[0:len(sequence)*8*8], maxlen=8)
	(c, maj, minor, rev, magic) = unpack("!BBBBL", string)
	
	if(c == 1 and magic == LPI_MAGIC):
		# We've got a header, decode the length
		string = __dechip_stream(sequence, stream[len(sequence)*8*8:len(sequence)*8*8 + len(sequence)*8*4], maxlen=4)
		data_len = unpack("!L", string)[0]
		
		#print "data_len: %d bytes" % data_len
		return (data_len, stream[len(sequence)*8*(12):])
	return (0, None)

def __chip_string(sequence, string):
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

def chip_string(sequence, string):
	stream = []
	
	# Hash the string
	msg_hash = hashlib.md5(string).digest()
	
	#print "msg digest: %s (%d bytes)" % (repr(msg_hash), len(msg_hash))
	
	# Build a packet header
	stream.extend(chip_header(sequence))
	# Encode the string length
	stream.extend(__chip_string(sequence, pack("!L", len(string))))
	
	# encode the string
	stream.extend(__chip_string(sequence,string))
	
	# encode a hash (for checksum function only)
	stream.extend(__chip_string(sequence, msg_hash))
	
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
	
def data_to_stream(string):
	stream = []
	
	ii = 0
	while ii < len(string):
		byte = unpack("B", string[ii])[0]
		
		if(byte & (1)):
			stream.append(1)
		else:
			stream.append(-1)
			
		ii += 1
	return stream
	
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
	
def dechip_byte(sequence, stream, printable_only=False):
	seq_len = len(sequence)
	match = "%s%s -_" % (string.ascii_letters, string.digits)
	
	ii = 0
	byte = 0
	while ii < 8:
		bit_stream = stream[(ii*seq_len):((ii*seq_len)+seq_len)]
		bit = dechip_bit(sequence, bit_stream)
		
		byte |= (bit << ii)
		
		ii += 1
	
	if((not printable_only) or pack('B',byte) in match):
		return byte
	
	return None

def dechip_bytes(sequence, byte_stream, printable_only=False):
	string = ""
	ii = 0
	while ii < len(byte_stream):
		char = dechip_byte(sequence, byte_stream[ii], printable_only)
		if(char != None):
			string += char
		ii += 1
		
	return string
	
def __dechip_stream(sequence, stream, printable_only=False, maxlen=None):
	# can only decode in modulo sequence length
	sequence_len = len(sequence)
	bytes = int(len(stream)/sequence_len)/8
		
	string = ""
	
	#print "decoding at most %d bytes" % data_len
	if(None == maxlen):
		maxlen = bytes
	
	ii = 0
	while string == "" and len(stream):
		while ii < maxlen:
		
			start = (ii*sequence_len*8)
			end = start + (sequence_len*8)
		
			#print " looking at bits %d to %d" % (start, end)
		
			byte = dechip_byte(sequence, stream[(ii*sequence_len*8):((ii*sequence_len*8) + (sequence_len*8))], printable_only)
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
	
def dechip_stream(sequence, stream):
	# Decode the header
	(data_len, stream) = dechip_header(sequence, stream)
	
	# If the magic bits don't match, ignore this shiznit
	if(data_len == 0 or stream == None):
		return None
	
	# Otherwise, now we know how many bytes are valid data
	# Decode it
	string = __dechip_stream(sequence, stream, maxlen=data_len)
	
	#print "str: %s" % string
	# Advance to the hash (CRC)
	
	# Decode the hash
	stream = stream[data_len*len(sequence)*8:]
	
	#print "%d bits left" % len(stream)
	
	digest = __dechip_stream(sequence, stream, maxlen=16)
	#print "digest: %s" % repr(digest)
	
	xmit_digest = hashlib.md5(string).digest()
	
	return (xmit_digest == digest, string)
	

def build_chip_table(len, seed=1):
	'''
	build_chip_table(len, seed):
	len: 
		size of matrix to build - result will be a len x len matrix of orthogonal sequences to
		be used in encoding data.
	seed: 
		should be +1 or -1.  Any value above 0 will be interpretted as 1, and <= 0 will be intepretted as -1
	
	Return Value:
		A len x len matrix of bits, encoded as +1 or -1 (not 0 or 1). Each one of these rows can be used as a chipping
		key to encode a message.  Each chipping key is orthogonal, meaning each encoding can carry up to 'len' number
		of messages. In order to decode a message, you must know which chipping key was used to encode it. Of course,
		it's possible to decode a bit-stream with every chipping sequence generated/known.  Because such a feat is 
		trivial, it is **highly** recommended to encrypt messages prior to encoding them with this library. 
	'''
	ret = []
	
	# Squash seed value to +/-1 
	if(seed > 0):
		seed = 1
	else:
		seed = -1
		
	# Initial sequence is [seed, seed],[seed,-seed]
	if(2 == len):
		return [[seed, seed],[seed,-1*seed]]
		
	# Recursively build a matrix of orthogonal sequences
	sub = build_chip_table(len/2, seed)
	
	# blah. kinda ugly code but it works
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

def test_file_encoding(filename, chip_len, channel_number):
	fd = open(filename, "r")
	
	# read file as a string
	byte_stream = fd.read()
	
	# pick an n-size chipping sequence
	chip_table = build_chip_table(chip_len, 1)
	key = chip_table[channel_number]
	
	# encode file's data into a bit-stream
	stream = chip_string(key, byte_stream)
	
	# decode it
	result = dechip_stream(key, stream)
	
	if(result != byte_stream):
		print "file test failed"
		return 0
	
	print "file test passed"
	return 1

def main():
	length = int(sys.argv[1])
	key = int(sys.argv[2])
	
	# make it even
	if(length % 2):
		length += 1
		
	if(key >= length):
		print "Key must be less than chip table size"
		
	try:
		filename = sys.argv[3]
		test_file_encoding(filename, length, key)
	except:
		pass
		
	table = build_chip_table(length, 1)
	
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
	
	string = dechip_stream(seq, summed, True)
	print "string: \'%s\'" % string
	
	sys.exit(0)
	ii = 0
	while ii < len(summed) - 64:
		
		string = dechip_stream(seq, summed[ii:], True)
		if(string != None):
			print "off: %d bits: string: %s" % (ii, string)
		
		string = dechip_stream(seq2, summed[ii:])
		if(string != None):
			print "off: %d bits: string2: %s" % (ii, string)
		
		ii += 1
	
	sys.exit(0)

	


if __name__ == "__main__":
    main()