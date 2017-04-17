#!/usr/bin/env python

'''
=============================================================================
  ___  _                  _    _ _             ___                _
 |   \(_)______ ___ _ __ | |__| (_)_ _  __ _  | __|__ _ _ _ _ ___| |_
 | |) | (_-<_-</ -_) '  \| '_ \ | | ' \/ _` | | _/ -_) '_| '_/ -_)  _|
 |___/|_/__/__/\___|_|_|_|_.__/_|_|_||_\__, | |_|\___|_| |_| \___|\__|
                                       |___/

=============================================================================

Packet sniffer in python using the pcapy python library

http://oss.coresecurity.com/projects/pcapy.html

Most of the server code comes from the binarytides website.
www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/

We'll be modifying this code base to suit our needs.

# ===========================================================================

20161024 - Clay

TODO:
- In order for the server to know what method the client is using we need an
  indicator on each packet, i.e., we need to know if the packets we're
  receiving are being bounced or not.

- It might also be useful to include an indicator that marks the beginning
  and/or end of a message.

#############################################################################
'''

# =======
# Imports
# =======

import socket
from struct import *
import datetime
import pcapy
import sys
import inspect

from optparse import OptionParser
parser = OptionParser()
parser.add_option ("-i", "--iface", dest="iface", default="foo",
                    help="Interface to listen on for smuggled data")
parser.add_option ("-s", "--srcip", dest="srcip", default="66.249.66.1",
                    help="Source address (possibly spoofed) we expect packets from")
parser.add_option ("-p", "--port", dest="listen_port", default="80",
                    help="Listening port")
(options, args) = parser.parse_args()

# ======
# Global
# ======

multiplier = 16777216
# Clear before/after each use; otherwise the array is repeatedly appended.
msg_array = []


# =============
# Main function
# =============

def main(argv):
    # List all devices
    devices = pcapy.findalldevs()
    dev = "foo" # The device we want to listen on
    listen_port = int(options.listen_port) # Port to listen on

    # print (devices)

    # We can parse devices from the command line
    # If no interface is specified ask user to enter device name to sniff
    if options.iface == "foo":
        print "Available devices are :"
        x = 0
        for d in devices:
            print " ", x , " ", d
            x += 1

        while True:
            dev = raw_input("Enter device number to sniff : ")
            try:
                device_choice = int(dev)
                if device_choice > -1 and device_choice <= x:
                    break
                else:
                    print "Device number not found"
            except ValueError:
                print "There was a problem with your choice (try a number)"

        dev = devices[device_choice]
    else:
        dev = options.iface

    # Ensure we have a proper device
    try:
        devices.index(dev)
    except ValueError:
        print "ERROR: Invalid listen interface"
        exit(0)

    if listen_port < 0 or listen_port > 65535:
        print "\nERROR: Destination port number is invalid, try a number 0 to 65,535\n"
        parser.print_help()
        exit(0)

    print "Sniffing device " + dev + " on port " + str(listen_port)

    '''
    Open device
    Arguments here are:
    - device
    - snaplen (maximum number of bytes to capture _per_packet_)
    - promiscious mode (1 for true)
    - timeout (in milliseconds)
    '''

    cap = pcapy.open_live(dev, 65536, 1, 0)

    # Start sniffing packets
    while (1):
        # The line below randomly generates an error. Adding try/except to fix
        try:
            (header, packet) = cap.next()
            # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet, listen_port)
        except IOError as e:
            print "[-] I/O error({0}): {1}".format(e.errno, e.strerror)
        except:
            print '[-] Exception: cap.next caught, moving on..'


# =========
# Functions
# =========

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


#
# Function to parse a packet
# TODO: this could be it's own Python module/class/library
def parse_packet(packet, listen_port):
    # Parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)  ## TODO: spell this out
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC: ' + eth_addr(packet[0:6]) + \
    # ' Source MAC: ' + eth_addr(packet[6:12])

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        ipid = iph[3]  # this seems to be correct
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        # print 'Version: ' + str(version) + ' IP Header Length: ' + str(ihl) + \
        # ' TTL: ' + str(ttl) + ' Protocol: ' + str(protocol) + \
        # ' SrcAddress: ' + str(s_addr) + ' DstAddress: ' + str(d_addr)

        # TCP protocol (Dissembling Ferret will focus on TCP channels)
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            # now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            window = tcph[6]
            tcph_length = doff_reserved >> 4

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            # Only display the packets sent to the listening port
            # - for some reason this doesn't print after the first message

            if str(dest_port) == str(listen_port):
                print 'Destination MAC: ' + eth_addr(packet[0:6]) + \
                      ' Source MAC: ' + eth_addr(packet[6:12]) + \
                      ' Protocol: ' + str(eth_protocol)
                print 'Version: ' + str(version) + ' IP Header Length: ' + str(ihl) + \
                      ' ID: ' + str(ipid) + \
                      ' TTL: ' + str(ttl) + ' Protocol: ' + str(protocol) + \
                      ' SrcAddress: ' + str(s_addr) + ' DstAddress: ' + str(d_addr)
                print 'SrcPort:  ' + str(source_port) + \
                      ' DstPort: ' + str(dest_port) + \
                      ' Sequence Number: ' + str(sequence) + \
                      ' Acknowledgement: ' + str(acknowledgement) + \
                      ' Window Size: ' + str(window) + \
                      ' TCP header length : ' + str(tcph_length)
                print 'Data: ' + data
                print 'Smuggled: ' + ''.join(msg_array)
                if str(window) == '1337':
                    decipher_iseq(sequence)
                elif str(window) == '1338':
                    decipher_ipid(ipid)
                elif str(window) == '1339':
                    decipher_bounce(sequence)
                elif str(window) == '7331':
                    print '[*] End Of Message'
                    # Reset the data array
                    data = []
                # TODO: now what?
                else:
                    print 'n0ise packet'

                if str(window) != '7331':
                    print '[*] Received so far: '
                    #for c in msg_array:
                    #    print '%s' % c
                    #print ''
                    # print 'Data: ' + data


        # ICMP Packets
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]
            # now unpack them :)
            icmph = unpack('!BBH', icmp_header)
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            # print 'Type: ' + str(icmp_type) + ' Code: ' + str(code) + \
            # ' Checksum: ' + str(checksum)
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
            # get data from the packet
            data = packet[h_size:]
        # print 'Data: ' + data

        # UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]
            # now unpack them :)
            udph = unpack('!HHHH', udp_header)
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            # print 'Source Port: ' + str(source_port) + \
            # ' Dest Port: ' + str(dest_port) + \
            # ' Length: ' + str(length) + \
            # ' Checksum: ' + str(checksum)
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
            # get data from the packet
            data = packet[h_size:]
            # print 'Data: ' + data
            # Some other IP packet like IGMP
            # else:
            # print 'Protocol other than TCP/UDP/ICMP'
            # print ''


# =========================================
# Functions for deciphering covert channels
# =========================================

# Decipher the initial sequence numbers
def decipher_iseq(seq):
    char = 0
    char = int(seq) / multiplier
    # Add seq to the global seq_array.
    msg_array.append(chr(char))
    print 'Received: %s' % chr(char)


def decipher_ipid(ipid):
    char = 0
    char = int(ipid) / 256
    msg_array.append(chr(char))
    print 'Received: %s' % chr(char)


def decipher_bounce(seq):
    char = 0
    char = int(seq - 1) / multiplier
    msg_array.append(chr(char))
    print 'Received: %s' % chr(char)


# =========
# Call main
# =========

if __name__ == "__main__":
    main(sys.argv)
