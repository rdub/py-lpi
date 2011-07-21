#!/usr/bin/env python

import lpi
import sys
import optparse
import base64
from pprint import pprint
from stat import *

def steg_encode(input_file, ksize=None, channel=None):
	# sensible defaults
	if(ksize == None):
		ksize = 8
	if(channel == None):
		channel = 0
		
	# make key table
	t = lpi.ChippingTable(ksize)
	# make encoder with selected key
	e = lpi.ChippingEncoder(t.key(channel))
	
	# read the data in 
	fd = open(input_file, "r")
	data = fd.read()
	
	# encode it into a bit-stream
	m = lpi.ChippingMessage(data)
	
	e.appendMessage(m)
	
	# read e.size() worth of random data
	rfd = open("/dev/urandom", "r")
	print "creating %d bytes of randomness..." % e.size()
	rdata = rfd.read(e.size())
	
	# Embed the data
	encoded_data = e.embedInData(rdata)
	
	outfile_name = "noise.txt"
	
	# Save the output as base64 data
	print "saving file as %s" % outfile_name
	wfd = open(outfile_name, "w+")
	b64_data = base64.b64encode(encoded_data)
	while(b64_data != ""):
		wfd.write(b64_data[0:80])
		wfd.write("\n")
		b64_data = b64_data[80:]
	wfd.close()
	
	return None
	
def steg_decode(input_file, ksize=None, channel=None):
	# Sensible defaults
	if(ksize == None):
		ksize = 8
	if(channel == None):
		channel = 0
		
	# make key table
	t = lpi.ChippingTable(ksize)
	# make encoder with selected key
	d = lpi.ChippingDecoder(t.key(channel))
	
	# open the image
	fd = open(input_file, "r")
	inp_data = fd.read()
	inp_data = inp_data.replace("\n", "")
	data = base64.b64decode(inp_data)
		
	string = d.recoverFromData(data)
	
	if(string):
		print "saving %d byte message..." % len(string)
		output_file = "decode.txt"
		fd = open(output_file, "w+")
		fd.write(string)
		fd.close()
		return string
		
	print "No data found!"
		
	return None

def main():
	parser = optparse.OptionParser(description='Encode or decode a text file into/from a base64 random sequence.', 
					usage="usage: %prog [options]")
	parser.add_option("-e", "--encode", metavar="input-file", help="the msg/file to encode")
	parser.add_option("-d", "--decode", metavar="output-file", help="where to write the stored output file")
	parser.add_option("-k", "--ksize", metavar="bits", help="keyspace size (2-64, even only)")
	parser.add_option("-c", "--channel", metavar="channel", help="the channel to look within")
	
	(options, args) = parser.parse_args()
	
	
	if(options.encode):
		steg_encode(options.encode, int(options.ksize), int(options.channel))
	if(options.decode):
		steg_decode(options.decode, int(options.ksize), int(options.channel))
	sys.exit(0)
	
	parser.print_help()
	
	sys.exit(1)
	
if __name__ == "__main__":
    main()