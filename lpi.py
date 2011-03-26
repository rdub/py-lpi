#!/usr/bin/env python

import sys
from pprint import pprint
from struct import *
import string
import hashlib
from math import log

# Encoded as bytes in the header
VERSION_MAJOR=1
VERSION_MINOR=0
VERSION_REVISION=0

# Encoded as network-order long
LPI_MAGIC=0xbeef1234

def stream_to_data(stream):
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
	

class ChippingMessage:
	
	data = ""
	data_len = 0
	data_hash = ""
	
	def __init__(self, message=""):
		self.data = message
		self.data_len = len(message)
		self.data_hash = hashlib.md5(self.data).digest()
		
	def append(self, string):
		self.data += string
		self.data_len += len(string)
		self.data_hash = hashlib.md5(self.data).digest()
		
		return self
	
	def reset(self):
		self.data = ""
		self.data_len = 0
		self.data_hash = hashlib.md5(self.data).digest()
		
		return self
		
	def toString(self):
		return pack("!L", self.data_len) + self.data + self.data_hash
		
	def toPrintableString(self):
		return "0x%04x: %s: (hash: %s)" % (self.data_len, repr(self.data), hashlib.md5(self.data).hexdigest())
	
	def __str__(self):
		return self.toPrintableString()
		
	def __repr__(self):
		return self.__str__()

class ChippingDecoder:
	key = None
	key_len = 0
	
	def __data_to_stream(self, string):
		stream = []

		ii = 0
		while ii < len(string):
			byte = unpack("B", string[ii])[0]
			bits = byte & (0x3)
			if(bits):
				stream.append(bits)
			else:
				stream.append(0)

			#if(byte & (1)):
			#	stream.append(1)
			#else:
			#	stream.append(-1)

			ii += 1
		return stream
	
	def __dot_product(self, symbol):
		# symbol and sequence are assumed to be the same length
		ii = 0
		product = 0
		while ii < self.key_len:
			product += self.key[ii]*symbol[ii]
			ii += 1

		if(product > 0):
			return 1
		return 0

	def __dechip_byte(self, stream):
		ii = 0
		byte = 0
		while ii < 8:
			bit_stream = stream[(ii*self.key_len):((ii*self.key_len)+self.key_len)]
			bit = self.__dot_product(bit_stream)

			byte |= (bit << ii)

			ii += 1

		return byte
	
	def __dechip_stream(self, stream, maxlen=None):
		# can only decode in modulo sequence length
		bytes = int(len(stream)/self.key_len)/8

		string = ""

		#print "decoding at most %d bytes" % data_len
		if(None == maxlen):
			maxlen = bytes

		ii = 0
		while ii < maxlen:

			start = (ii*self.key_len*8)
			end = start + (self.key_len*8)

			#print " looking at bits %d to %d" % (start, end)

			#byte = dechip_byte(sequence, stream[(ii*sequence_len*8):((ii*sequence_len*8) + (sequence_len*8))], printable_only)
			byte = self.__dechip_byte(stream[start:end])

			#print "0x%x" % byte

			b_str = pack("B", byte)

			#print b_str

			string += b_str

			ii += 1

		return string
		
	def __decode_header(self, bitstream):
		if(self.key == None):
			raise Exception("No key set")
		
		string = self.__dechip_stream(bitstream[0:self.key_len*8*8], maxlen=8)
		(c, maj, minor, rev, magic) = unpack("!BBBBL", string)

		if(c == 1 and magic == LPI_MAGIC):
			# We've got a header, decode the length
			string = self.__dechip_stream(bitstream[self.key_len*8*8:self.key_len*8*8 + self.key_len*8*4], maxlen=4)
			data_len = unpack("!L", string)[0]

			#print "data_len: %d bytes" % data_len
			return (data_len, bitstream[self.key_len*8*(12):])
		return (0, None)
		
	
	def decodeBitstream(self, bitstream):
		if(self.key == None):
			raise Exception("No key set")
		
		(data_len, stream) = self.__decode_header(bitstream)
		
		if(data_len):
			string = self.__dechip_stream(stream, data_len)
			
			# Decode the hash
			stream = stream[data_len*self.key_len*8:]

			#print "%d bits left" % len(stream)

			digest = self.__dechip_stream(stream, maxlen=16)
			#print "digest: %s" % repr(digest)

			xmit_digest = hashlib.md5(string).digest()
			
			if(xmit_digest == digest):
				return string

		return None
		
	def recoverFromData(self, data):
		if(self.key == None):
			raise Exception("Key not set")
		
		bit_stream = self.__data_to_stream(data)
		return self.decodeBitstream(bit_stream)
	
	def set_key(self, key):
		if(len(key) & 1):
			raise Exception("Key length must be even")
		self.key = key
		self.key_len = len(key)
		return self
	
	def __init__(self, key=None):
		self.key = None
		self.key_len = 0
		if(key != None):
			self.set_key(key)

class ChippingEncoder:
	data_stream = []
	key = None
	key_len = 0
	msg_count = 0
	cached_size = 0
	
	def __encode_string(self, string):
		if(len(string) == 0):
			raise Exception("No data to encode")
		if(self.key == None):
			raise Exception("No key set")
			
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
				symbol = map(lambda x:bit*x, self.key)
				stream.extend(symbol)

				ii <<= 1

			jj += 1
		return stream
		
	def __interfere(self, x, y):
		if(x == None):
			return y
		if(y == None):
			return x
		return x+y
	
	def __encode_header(self):
		string = "\x01" + pack("!BBBL", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, LPI_MAGIC)
		return self.__encode_string(string)
		
	def __stream_bit_to_data_bit(self, bit, squashToOne=True):
		if(bit > 0):
			if(squashToOne):
				return 1
			return bit
		return 0
	
	def reset(self):
		self.data_stream = []
		self.msg_count = 0
	
	def appendMessage(self, message):
		if(self.msg_count > 2):
			raise Exception("Too many messages")
		self.msg_count += 1
		new_stream = self.__encode_header()
		new_stream.extend(self.__encode_string(message.toString()))
		self.data_stream = map(lambda x,y: self.__interfere(x,y), self.data_stream, new_stream)
		self.cached_size = len(self.encodedBitstream())
		return self
	
	def encodedBitstream(self):
		return self.data_stream
		
	def embedInData(self, output_data_str):
		if(len(self.data_stream) == 0):
			raise Exception("No data to encode")
			
		bitstream = self.encodedBitstream()
		b_max = 0
		for n in bitstream:
			b_max = max(b_max, n)
		
		#lsbs = int((log(b_max)/log(2.0)) + 1)
		
		#print "LSBs needed: %d" % lsbs
		#mask = 0xFF
		#mask <<= lsbs
		#mask &= 0xFF
		#print "mask 0x%x" % mask
		#return 
		
		data = list(output_data_str)
		
		b_len = len(bitstream)
		d_len = len(data)
		
		if(d_len < b_len):
			raise Exception("Data not long enough")
		
		for n in range(0, b_len):
			# Steg, baby.
			byte = unpack("B", data[n])[0]
			
			# Steal the LSBs
			byte &= 0xFC
			byte |= self.__stream_bit_to_data_bit(bitstream[n], False)
			
			c = pack("B", byte)
			
			data[n] = c
		
		return "".join(data)
		
	def size(self):
		return self.cached_size
	
	def set_key(self, key):
		self.key = key
		self.key_len = len(key)
		
		if(self.key_len & 0x1):
			raise Exception("key length must be even")
	
	def __init__(self, key=None):
		self.data_stream = []
		self.key = []
		self.key_len = 0
		self.msg_count = 0
		self.cached_size = 0
		if(key != None):
			self.set_key(key)
		
	def __repr__(self):
		return "keysize: %d encoded-data: %d bytes" % (self.key_len, len(self.data_stream))
	def __str__(self):
		return self.__repr__()
	


class ChippingTable:
	table = []
	
	def __build_chip_table(self, len, seed=1):
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
		sub = self.__build_chip_table(len/2, seed)

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
		
	def key(self, index):
		return self.table[index]
	
	def __init__(self, size):
		self.table = self.__build_chip_table(size)

	def __repr__(self):
		return repr(self.table)
	def __str__(self):
		return repr(self.table)

def class_test():
	key_size = 16
	data_size = key_size * 8192
	test_cases = [
					((key_size/2) + 1, "This is a test.\nThis is only a test.\nDon't Panic.\n"),
					(1, "For every action, there is an equal and opposite reaction."),
					(key_size - 1, "What you talkin' bout, willis?"),
				]
	
	print "Generating %d random bytes" % data_size
	r_file = open("/dev/urandom", "r")
	noise = r_file.read(data_size)
	
	print "Generating %d channel chipping table..." % key_size
	t = ChippingTable(key_size)
	#pprint(t)
	
	print "Testing encoder..."
	e = ChippingEncoder()
	
	for (channel, msg) in test_cases:
		print "  Encoding msg: %s into channel %d" % (repr(msg), channel)
		k = t.key(channel)
		m = ChippingMessage(msg)
		e.set_key(k)
		e.appendMessage(m)
		

	print "  encoded into %d bytes..." % e.size()
	
	print "  generating bit-stream..."
	b = e.encodedBitstream()
	
	print "  embedding bit-stream in noise..."
	steg_noise = e.embedInData(noise)
	
	print "Testing decoder (bit-stream)..."
	d = ChippingDecoder()
	
	for (channel, msg) in test_cases:
		print "  Decoding channel %d..." % channel
		k = t.key(channel)
		d.set_key(k)
		test_string = d.decodeBitstream(b)
		
		if(test_string == msg):
			print "    PASS %s" % repr(test_string)
		else:
			print "    FAIL %s" % repr(test_string)
	
	print "Testing decoder (steganographic)..."
	for (channel, msg) in test_cases:
		print "  Decoding channel %d..." % channel
		k = t.key(channel)
		d.set_key(k)
		test_string = d.recoverFromData(steg_noise)
		if(test_string == msg):
			print "    PASS %s" % repr(test_string)
		else:
			print "    FAIL"
	
	print "Done."	
	

if __name__ == "__main__":
    class_test()