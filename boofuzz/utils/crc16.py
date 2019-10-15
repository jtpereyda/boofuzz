# -*- coding: UTF-8 -*-

"""
 Translation from a C code posted to a forum on the Internet.

 @translator Thomas Schmid
 @url https://raw.githubusercontent.com/mitshell/libmich/master/libmich/utils/CRC16.py
"""


def reflect(crc, bitnum):
    # reflects the lower 'bitnum' bits of 'crc'
    j = 1
    crcout = 0

    for b in range(bitnum):
        i = 1 << (bitnum - 1 - b)
        if crc & i:
            crcout |= j
        j <<= 1
    return crcout


def crcbitbybit(p):
    # bit by bit algorithm with augmented zero bytes.
    crc = 0

    for i in range(len(p)):
        c = p[i]
        c = reflect(ord(c), 8)
        j = 0x80
        for b in range(16):
            bit = crc & 0x8000
            crc <<= 1
            crc &= 0xFFFF
            if c & j:
                crc |= 1
            if bit:
                crc ^= 0x3D65
            j >>= 1
            if j == 0:
                break

    for i in range(16):
        bit = crc & 0x8000
        crc <<= 1
        if bit:
            crc ^= 0x3D65

    crc = reflect(crc, 16)
    return crc ^ 0xFFFF


# CRC-16/DNP : used in DNP3 protocol
class CRC16_DNP(object):
    """ 
    Class interface, like the Python library's cryptographic
    hash functions (which CRC's are definitely not.)
    """

    def __init__(self, string=""):
        self.val = 0
        if string:
            self.update(string)

    def update(self, string):
        self.val = crcbitbybit(string)

    def checksum(self):
        return chr(self.val >> 8) + chr(self.val & 0xFF)

    def intchecksum(self):
        return self.val

    def hexchecksum(self):
        return "%04x" % self.val

    def copy(self):
        clone = CRC16_DNP()
        clone.val = self.val
        return clone
