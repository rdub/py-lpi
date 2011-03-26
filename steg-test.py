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
	pprint(pixel_data)
	
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
	pprint(decode.tostring())
	data = list(decode.tostring())
	
	string = d.recoverFromData(data)
	
	if(string):
		print "saving %d byte message..." % len(string)
		fd = open(output_file, "w+")
		fd.write(string)
		fd.close()
	print "No data found!"
		
	return None

def main():
	parser = optparse.OptionParser(description='Encode a file into an image, below the noise floor.')
	parser.add_option("-e", "--encode", help="the file to encode")
	parser.add_option("-d", "--decode", help="File image to decode")
	parser.add_option("-k", "--ksize", help="keyspace size (2-64, even only)")
	parser.add_option("-c", "--channel", help="the channel to look within")
	
	(options, args) = parser.parse_args()
	
	if(len(args) == 0):
		sys.exit(-1)
	
	if(options.encode):
		steg_encode(options.encode, args[0], options.ksize, options.channel)
	if(options.decode):
		steg_decode(options.decode, args[0], options.ksize, options.channel)
	
	sys.exit(-1)
	
	
	k_len = int(sys.argv[1])
	channel = int(sys.argv[2])
	data_file = sys.argv[3]
	img_target = sys.argv[4]
	
	t = lpi.ChippingTable(k_len)
	e = lpi.ChippingEncoder(t.key(channel))
	d = lpi.ChippingDecoder(t.key(channel))
	
	fd = open(data_file, "r")
	data = fd.read()
	
	m = lpi.ChippingMessage(data)
	
	e.appendMessage(m)
	
	img = Image.open(img_target)
	pixel_data = list(img.tostring())
	size = len(pixel_data)
	
	if(size < e.size()):
		print "image is not large enough - should be at least %d bytes of pixel data" % e.size()
		sys.exit(-1)
	print "%d bytes of pixels" % size
	print "%d bytes of data" % e.size()
	
	# Embed the data
	pixel_data = e.embedInData(pixel_data)
	
	# put it back into the image
	img.fromstring("".join(pixel_data))
	
	options = {}
	options['quality'] = 1.0
	
	# Save the image
	img.save("output-changed.png", format="PNG", options=options)
	
	# open the image
	decode = Image.open("output-changed.png")
	data = list(decode.tostring())
	
	string = d.recoverFromData(data)
	
	if(string):
		print "data:\n%s" % string
	else:
		print "data not found!"
	
if __name__ == "__main__":
    main()