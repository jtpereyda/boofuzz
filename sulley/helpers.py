import socket
import platform
import ctypes as c
import zlib

# noinspection PyPep8Naming
import struct
import re


def get_max_udp_size():
    """
    Crazy CTypes magic to do a getsockopt() which determines the max UDP payload size in a platform-agnostic way.

        @rtype:  long
        @return: The maximum length of a UDP packet the current platform supports
    """
    windows = platform.uname()[0] == "Windows"
    mac = platform.uname()[0] == "Darwin"
    linux = platform.uname()[0] == "Linux"
    lib = None

    if windows:
        sol_socket = c.c_int(0xffff)
        sol_max_msg_size = 0x2003
        lib = c.WinDLL('Ws2_32.dll')
        opt = c.c_int(sol_max_msg_size)
    elif linux or mac:
        if mac:
            lib = c.cdll.LoadLibrary('libc.dylib')
        elif linux:
            lib = c.cdll.LoadLibrary('libc.so.6')
        sol_socket = c.c_int(socket.SOL_SOCKET)
        opt = c.c_int(socket.SO_SNDBUF)

    else:
        raise Exception("Unknown platform!")

    ulong_size = c.sizeof(c.c_ulong)
    buf = c.create_string_buffer(ulong_size)
    bufsize = c.c_int(ulong_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    lib.getsockopt(
        sock.fileno(),
        sol_socket,
        opt,
        buf,
        c.pointer(bufsize)
    )

    return c.c_ulong.from_buffer(buf).value


def calculate_four_byte_padding(string, character="\x00"):
    return character * ((4 - (len(string) & 3)) & 3)


def crc16(string, value=0):
    """
    CRC-16 poly: p(x) = x**16 + x**15 + x**2 + 1
    """
    crc16_table = []
    for byte in range(256):
        crc = 0

        for bit in range(8):
            if (byte ^ crc) & 1:
                crc = (crc >> 1) ^ 0xa001  # polly
            else:
                crc >>= 1

            byte >>= 1

        crc16_table.append(crc)

    for ch in string:
        value = crc16_table[ord(ch) ^ (value & 0xff)] ^ (value >> 8)

    return value


def crc32(string):
    return zlib.crc32(string) & 0xFFFFFFFF


def uuid_bin_to_str(uuid):
    """
    Convert a binary UUID to human readable string.
    """
    (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
    (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

    return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)


def uuid_str_to_bin(uuid):
    """
    Ripped from Core Impacket. Converts a UUID string to binary form.
    """
    uuid_re = r'([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})'

    matches = re.match(uuid_re, uuid)

    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: long(x, 16), matches.groups())

    uuid = struct.pack('<LHH', uuid1, uuid2, uuid3)
    uuid += struct.pack('>HHL', uuid4, uuid5, uuid6)

    return uuid


def hex_str(s):
    """
    Returns a hex-formatted string based on s.
    :param s: Some string.
    :type s: str

    :return: Hex-formatted string representing s.
    :rtype: str
    """
    return ' '.join("{:02x}".format(ord(b)) for b in s)
