#!/usr/bin/env python

import lpi
import sys
from PIL import Image
import optparse
from pprint import pprint


def steg_encode(data_file, img_file, ksize=None, channel=None):
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
	fd = open(data_file, "r")
	data = fd.read()
	
	# encode it into a bit-stream
	m = lpi.ChippingMessage(data)
	
	e.appendMessage(m)
	
	# open the image file
	img = Image.open(img_file)
	pixel_data = list(img.tostring())
	size = len(pixel_data)
	
	if(size < e.size()):
		print "image is not large enough - should be at least %d bytes of pixel-data" % e.size()
		sys.exit(-1)
	print "%d bytes of pixel-data" % size
	print "%d bytes of bit-stream data" % e.size()
	
	# Embed the data
	pixel_data = e.embedInData(pixel_data)
	#pprint(pixel_data)
	
	# put it back into the image object
	img.fromstring("".join(pixel_data))
	
	outfile_name = img_file.split(".")[0] + ".embedded.png"
	
	options = {}
	options['quality'] = 100.0
	
	# Save the image
	print "saving file as %s" % outfile_name
	img.save(outfile_name, format="PNG", options=options)
	
	return None
	
def steg_decode(output_file, img_file, ksize=None, channel=None):
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
	decode = Image.open(img_file)
	#pprint(decode.tostring())
	
	data = list(decode.tostring())
	
	string = d.recoverFromData(data)
	
	if(string):
		print "saving %d byte message..." % len(string)
		fd = open(output_file, "w+")
		fd.write(string)
		fd.close()
		return string
		
	print "No data found!"
		
	return None

def main():
	parser = optparse.OptionParser(description='Encode or decode a file into/from a PNG image.', 
					usage="usage: %prog [options] image-file.png")
	parser.add_option("-e", "--encode", metavar="input-file", help="the msg/file to encode")
	parser.add_option("-d", "--decode", metavar="output-file", help="where to write the stored output file")
	parser.add_option("-k", "--ksize", metavar="bits", help="keyspace size (2-64, even only)")
	parser.add_option("-c", "--channel", metavar="channel", help="the channel to look within")
	
	(options, args) = parser.parse_args()
	
	if(len(args) != 0):
		if(options.encode):
			steg_encode(options.encode, args[0], int(options.ksize), int(options.channel))
		if(options.decode):
			steg_decode(options.decode, args[0], int(options.ksize), int(options.channel))
		sys.exit(0)
	
	parser.print_help()
	
	sys.exit(1)
	
if __name__ == "__main__":
    main()