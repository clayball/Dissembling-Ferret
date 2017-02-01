#!/usr/bin/env python

'''
=======================================================================
  ___  _                  _    _ _             ___                _
 |   \(_)______ ___ _ __ | |__| (_)_ _  __ _  | __|__ _ _ _ _ ___| |_
 | |) | (_-<_-</ -_) '  \| '_ \ | | ' \/ _` | | _/ -_) '_| '_/ -_)  _|
 |___/|_/__/__/\___|_|_|_|_.__/_|_|_||_\__, | |_|\___|_| |_| \___|\__|
                                       |___/

=======================================================================


Packet sniffer in python using the pcapy python library

http://oss.coresecurity.com/projects/pcapy.html

Most of the server code comes from the binarytides website.
www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/

We'll be modifying this code base to suit our needs.

##############################################################################

20161024 - Clay

TODO:
- In order for the server to know what method the client is using we need an
  indicator on each packet, i.e., we need to know if the packets we're
  receiving are being bounced or not.

- It might also be useful to include an indicator that marks the beginning and
  end of a message.

##############################################################################
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
    print devices

    # Ask user to enter device name to sniff
    print "Available devices are :"
    for d in devices:
        print d

    dev = raw_input("Enter device name to sniff : ")

    print "Sniffing device " + dev

    '''
    open device
    Arguments here are:
    device
    snaplen (maximum number of bytes to capture _per_packet_)
    promiscious mode (1 for true)
    timeout (in milliseconds)
    '''

    cap = pcapy.open_live(dev, 65536, 1, 0)

    # Start sniffing packets
    while (1):
        # The line below randomly generates an error. Adding try/except to fix
        try:
            (header, packet) = cap.next()
            # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet)
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
def parse_packet(packet):
    # Parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC: ' + eth_addr(packet[0:6]) + \
    # ' Source MAC: ' + eth_addr(packet[6:12]) + \
    # ' Protocol: ' + str(eth_protocol)

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
            tcph_length = doff_reserved >> 4

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            # Only display the packets sent to port 31337
            # - for some reason this doesn't print after the first message
            # TODO: make this configurable or via command-line
            if str(dest_port) == '31337':
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
                      ' Acknowledgement : ' + str(acknowledgement) + \
                      ' TCP header length : ' + str(tcph_length)
                print 'Data: ' + data
                if str(ttl) == '64':
                    decipher_iseq(sequence)
                elif str(ttl) == '68':
                    decipher_ipid(ipid)
                elif str(ttl) == '60': ## TODO: change this.. using ttl here is not a good idea!
                    print '[*] End Of Message'
                # TODO: now what?
                else:
                    print 'n0ise packet'

                print '[*] Received so far: '
                for c in msg_array:
                    print '%s' % c
                print ''

                # print 'Data: ' + data

        '''
        NOTE: We aren't using IMCP or UDP at the moment. Leaving the code
               here just in case we'd like to in the future.
        '''
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
    char = int(seq)
    char -= 1
    msg_array.append(chr(char))
    print 'Received: %s' % chr(char)


# =========
# Call main
# =========

if __name__ == "__main__":
    main(sys.argv)
