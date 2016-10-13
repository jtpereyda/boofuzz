"""
This file contains constants for the IPv4 protocol.
"""
IPV4_PROTOCOL_UDP = 0x11
#: Theoretical maximum length of a UDP packet, based on constraints in the UDP
#: packet format.
#: WARNING! a UDP packet cannot actually be this long in the context of IPv4!
UDP_MAX_LENGTH_THEORETICAL = 65535
#: Theoretical maximum length of a UDP payload based on constraints in the
#: UDP and IPv4 packet formats.
#: WARNING! Some systems may set a payload limit smaller than this.
UDP_MAX_PAYLOAD_IPV4_THEORETICAL = 65507
