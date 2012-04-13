"""
STUN: Simple Traversal of UDP through NAT
Gizmo binds this service on UDP port 5004 / 5005
http://www.vovida.org/
"""

from sulley import *

########################################################################################################################
s_initialize("binding request")

# message type 0x0001: binding request.
s_static("\x00\x01")

# message length.
s_sizer("attributes", length=2, endian=">", name="message length", fuzzable=True)

# message transaction id.
s_static("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

if s_block_start("attributes"):
    # attribute type
    #   0x0001: mapped address
    #   0x0003: change request
    #   0x0004: source address
    #   0x0005: changed address
    #   0x8020: xor mapped address
    #   0x8022: server
    s_word(0x0003, endian=">")

    s_sizer("attribute", length=2, endian=">", name="attribute length", fuzzable=True)

    if s_block_start("attribute"):
        # default valid null block
        s_string("\x00\x00\x00\x00")
    s_block_end()

s_block_end()

# toss out some large strings when the lengths are anything but valid.
if s_block_start("fuzz block 1", dep="attribute length", dep_value=4, dep_compare="!="):
    s_static("A"*5000)
s_block_end()

# toss out some large strings when the lengths are anything but valid.
if s_block_start("fuzz block 2", dep="message length", dep_value=8, dep_compare="!="):
    s_static("B"*5000)
s_block_end()


########################################################################################################################
s_initialize("binding response")

# message type 0x0101: binding response