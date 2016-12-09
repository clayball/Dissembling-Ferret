Firewall Tests
==============

The test data we'll be sending will be fake:

- social security numbers
- credit card numbers (name? security code?)

The purpose of a firewall, next-gen or next-next-gen, is not to identify and
block all possible ways that data can be exfiltrated from a network..
especially when steganography is used. For this reason, we'll include some
test that we believe the firewall will easily catch along with tests that
include the use of steganography.


## Covert Channel Tests

A plus sign next to the item means the code has been written for the test.

+ IP Identification field

    This likely will NOT work
    
+ Initial sequence numbers

    This should slip through the cracks

+ Bounce ACK sequence numbers

    This spoofs the source address (reveals our server)
    
- Smuggle data in DNS packets

    If we use a rogue DNS server then we will likely be detected.
    - Spoof source with destination of 8.8.8.8.

- Smuggle data over HTTPS

    This method is louder than previous methods but can still be obscure and
    difficult to detect.

