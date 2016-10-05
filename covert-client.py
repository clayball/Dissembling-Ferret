#!/usr/bin/env python

# Send a message using TCP sequence numbers and ttl. The value is used to
# inject noise into the channel.

# Sequence numbers have a generous size limit of 32bits.
#
# The sequence numbers are converted to ASCII by dividing by 16777216 which is
# a representation of 65536*256. [1] see README


from scapy.all import *
import os


# Global variables
thishost = os.uname()[1]
divisor = 16777216
message = 'hello from ' + thishost


##############################################################################
# Functions

# Convert message
# Lots of options here but we're going to convert each letter of the message
# and send one letter at a time.
def convert_message():
	print '[*] converting message: %s' % message
	for char in message:
		c = ord(char)
		print '%s = %d' % (char, c)
	return c



##############################################################################
# Main program

convert_message()
