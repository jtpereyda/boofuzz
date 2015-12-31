from __future__ import absolute_import
import math
import struct
from .. import helpers


def bind(uuid, version):
    """
    Generate the data necessary to bind to the specified interface.
    """

    major, minor = version.split(".")

    major = struct.pack("<H", int(major))
    minor = struct.pack("<H", int(minor))

    bind_request = "\x05\x00"  # version 5.0
    bind_request += "\x0b"  # packet type = bind (11)
    bind_request += "\x03"  # packet flags = last/first flag set
    bind_request += "\x10\x00\x00\x00"  # data representation
    bind_request += "\x48\x00"  # frag length: 72
    bind_request += "\x00\x00"  # auth length
    bind_request += "\x00\x00\x00\x00"  # call id
    bind_request += "\xb8\x10"  # max transmit frag (4280)
    bind_request += "\xb8\x10"  # max recv frag (4280)
    bind_request += "\x00\x00\x00\x00"  # assoc group
    bind_request += "\x01"  # number of ctx items (1)
    bind_request += "\x00\x00\x00"  # padding
    bind_request += "\x00\x00"  # context id (0)
    bind_request += "\x01"  # number of trans items (1)
    bind_request += "\x00"  # padding
    bind_request += helpers.uuid_str_to_bin(uuid)  # abstract syntax
    bind_request += major  # interface version
    bind_request += minor  # interface version minor

    # transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
    bind_request += "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
    bind_request += "\x02\x00\x00\x00"

    return bind_request


def bind_ack(data):
    """
    Ensure the data is a bind ack and that the
    """

    # packet type == bind ack (12)?
    if data[2] != "\x0c":
        return False

    # ack result == acceptance?
    if data[36:38] != "\x00\x00":
        return False

    return True


def request(opnum, data):
    """
    Return a list of packets broken into 5k fragmented chunks necessary to make the RPC request.
    """

    frag_size = 1000  # max frag size = 5840?
    frags = []

    num_frags = int(math.ceil(float(len(data)) / float(frag_size)))

    for i in xrange(num_frags):
        chunk = data[i * frag_size:(i + 1) * frag_size]
        frag_length = struct.pack("<H", len(chunk) + 24)
        alloc_hint = struct.pack("<L", len(chunk))

        flags = 0
        if i == 0:
            flags |= 0x1  # first frag
        if i == num_frags - 1:
            flags |= 0x2  # last frag

        request_buffer = "\x05\x00"  # version 5.0
        request_buffer += "\x00"  # packet type = request (0)
        request_buffer += struct.pack("B", flags)  # packet flags
        request_buffer += "\x10\x00\x00\x00"  # data representation
        request_buffer += frag_length  # frag length
        request_buffer += "\x00\x00"  # auth length
        request_buffer += "\x00\x00\x00\x00"  # call id
        request_buffer += alloc_hint  # alloc hint
        request_buffer += "\x00\x00"  # context id (0)
        request_buffer += struct.pack("<H", opnum)  # opnum
        request_buffer += chunk

        frags.append(request_buffer)

    # you don't have to send chunks out individually. so make life easier for the user and send them all at once.
    return "".join(frags)