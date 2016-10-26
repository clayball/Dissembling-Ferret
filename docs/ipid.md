# RFC6864 - Updated Specification of the IPv4 ID Field

Relevant information regarding the IP Identification field.


- February 2013
- Source: https://tools.ietf.org/html/rfc6864

## Abstract

The IPv4 Identification (ID) field enables fragmentation and reassembly and,
as currently specified, is required to be unique within the maximum lifetime
for all datagrams with a given source address/destination address/protocol
tuple.  If enforced, this uniqueness requirement would limit all connections
to 6.4 Mbps for typical datagram sizes. Because individual connections commonly
exceed this speed, it is clear that existing systems violate the current
specification. This document updates the specification of the IPv4 ID field in
RFCs 791, 1122, and 2003 to more closely reflect current practice and to more
closely match IPv6 so that the field's value is defined only when a datagram is
actually fragmented. It also discusses the impact of these changes on how
datagrams are used.


## Implications



