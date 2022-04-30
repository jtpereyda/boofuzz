import math
import struct

from ..helpers import crc16


def dnp3(data, control_code=b"\x44", src=b"\x00\x00", dst=b"\x00\x00"):
    num_packets = int(math.ceil(float(len(data)) / 250.0))
    packets = []

    for i in range(num_packets):
        packet_slice = data[i * 250 : (i + 1) * 250]

        p = b"\x05\x64"
        p += len(packet_slice).to_bytes(1, "little")
        p += control_code
        p += dst
        p += src

        chksum = struct.pack("<H", crc16(p))

        p += chksum

        num_chunks = int(math.ceil(float(len(packet_slice) / 16.0)))

        # insert the fragmentation flags / sequence number.
        # first frag: 0x40, last frag: 0x80

        frag_number = i

        if i == 0:
            frag_number |= 0x40

        if i == num_packets - 1:
            frag_number |= 0x80

        p += frag_number.to_bytes(1, "little")

        for x in range(num_chunks):
            chunk = packet_slice[i * 16 : (i + 1) * 16]
            chksum = struct.pack("<H", crc16(chunk))
            p += chksum + chunk

        packets.append(p)

    return packets
