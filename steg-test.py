#!/usr/bin/env python

import lpi
import sys
from PIL import Image
import StringIO
from struct import *

def main():
	sequence_len = int(sys.argv[1])
	channel = int(sys.argv[2])
	filename = sys.argv[3]
	img_target = sys.argv[4]
	
	key_table = lpi.build_chip_table(sequence_len)
	
	key = key_table[channel]
	
	options = {}
	options['quality'] = 1.0
	
	fd = open(filename, "r")
	data = fd.read()	
	
	bit_stream = lpi.chip_string(key, data)
	
	img = Image.open(img_target)
	img.save("output-orig.png", format="PNG", options=options)
	data = list(img.tostring())
	
	size = len(data)
	
	if(size < len(bit_stream)):
		print "image is not large enough - should be at least %d bytes of pixel data" % len(bit_stream)
		sys.exit(-1)
	print "%d bytes of pixels" % size
	print "%d bytes of data" % len(bit_stream)
	
	for n in range(0, min(size, len(bit_stream))):
		# Steg, baby.
		byte = unpack("B", data[n])[0]
		byte &= 0xFE
		byte |= lpi.stream_bit_to_bit(bit_stream[n])
		c = pack("B", byte)
		data[n] = c
	
	stream = lpi.data_to_stream(data[0:len(bit_stream)])
		
	(okay, tmp) = lpi.dechip_stream(key, stream)
	if(not okay):
		print "Failed to decode in-memory representation..."
	#print "tmp: %s" % tmp
	#print ""
	#print ""
	
	img.fromstring("".join(data))
	img.save("output-changed.png", format="PNG", options=options)
	
	
	decode = Image.open("output-changed.png")
	data = list(decode.tostring())
	
	stream = lpi.data_to_stream(data)
	
	(okay, string) = lpi.dechip_stream(key, stream)
	if(okay):
		print "data:\n%s" % string
	else:
		print "data (corrupt): %s" % string
	
	
	
	
if __name__ == "__main__":
    main()