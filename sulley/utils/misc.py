import re
import struct


########################################################################################################################
def crc16 (string, value=0):
    '''
    CRC-16 poly: p(x) = x**16 + x**15 + x**2 + 1
    '''

    crc16_table = []

    for byte in range(256):
         crc = 0

         for bit in range(8):
             if (byte ^ crc) & 1: crc = (crc >> 1) ^ 0xa001  # polly
             else:                crc >>= 1

             byte >>= 1

         crc16_table.append(crc)

    for ch in string:
        value = crc16_table[ord(ch) ^ (value & 0xff)] ^ (value >> 8)

    return value


########################################################################################################################
def uuid_bin_to_str (uuid):
    '''
    Convert a binary UUID to human readable string.
    '''

    (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
    (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

    return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)


########################################################################################################################
def uuid_str_to_bin (uuid):
    '''
    Ripped from Core Impacket. Converts a UUID string to binary form.
    '''

    matches = re.match('([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})', uuid)

    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: long(x, 16), matches.groups())

    uuid  = struct.pack('<LHH', uuid1, uuid2, uuid3)
    uuid += struct.pack('>HHL', uuid4, uuid5, uuid6)

    return uuid
