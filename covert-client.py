#!/usr/bin/env python

# Send a message using TCP sequence numbers and ttl. The value is used to
# inject noise into the channel.

# Sequence numbers have a generous size limit of 32bits.
#
# The sequence numbers are converted to ASCII by dividing by 16777216 which is
# a representation of 65536*256. [1] see README

# TODO:
# - add try, except where appropriate

from scapy.all import *
import os
import sys
import random


# Global variables
thishost = os.uname()[1]
multiplier = 16777216        # the server will be performing the division
message = 'hello from ' + thishost
seq_array = []
destination = '127.0.0.1'
# spoof our source
source = '66.249.66.1'  # Spoof crawl-66-249-66-1.googlebot.com


##############################################################################
# Functions

# Convert message
# Lots of options here but we're going to convert each letter of the message
# to its decimal equivalent.. which will be multiplied by the multiplier.
def convert_message():
	print '[*] converting message: %s' % message
	for char in message:
		c = ord(char)
		# While we are here, might as well generate our SYN packet sequence
		# number.
		seq = c * multiplier
		# Add seq to the global seq_array.
		seq_array.append(seq)
		print '%s=%d, seq=%d' % (char, c, seq)

def add_n0ise():
	print '[*] adding n0ise..'
	y = seq_array[i]
	# Add some randomness for schlitz n giggles
	randy = random.randint(-999999999, 999999999)
	pkt.seq = y + randy
	# Signal noisy packet
	pkt.window = 8182 - random.randint(23, 275)
	send(pkt)


##############################################################################
# Main program

convert_message()

# Our seq_array has been built. Time to craft our packet and iterate over our
# message.

# How long is our message. We can use this when adding noise. If we use the
# ttl then this will be easy to crack. We might be able to create an algorithm
# that's complex enough to at least frustrate our adversaries.
msglen = len(seq_array)

pkt = IP(src=source, dst=destination, ttl=48)/TCP(dport=80, flags='S')

# For now we'll send the message, without noise.
i = 0
k = 8192 # window size
for s in seq_array:
	add_n0ise()
	pkt.window = k
	pkt.seq = seq_array[i]
	send(pkt)
	i += 1


