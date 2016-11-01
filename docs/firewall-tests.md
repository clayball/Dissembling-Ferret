Firewall Tests
==============

The test data we'll be sending will be fake:
- social security numbers
- credit card numbers (name? security code?)


TCP Covert Channels
-------------------

- IP Identification field

    This likely will NOT work
    
- Initial sequence numbers

    This should slip through the cracks

- Bounce ACK sequence numbers

    This spoofs the source address (reveals our server)
