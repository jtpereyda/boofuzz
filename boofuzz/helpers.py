import socket
import platform
import ctypes as c
import zlib

# noinspection PyPep8Naming
import struct
import re
import signal
import time
import ip_constants


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


def _ones_complement_sum_carry_16(a, b):
    """
    Compute ones complement and carry at 16 bits.
    :type a: int
    :type b: int
    :return: Sum of a and b, ones complement, carry at 16 bits.
    """
    pre_sum = a + b
    return (pre_sum & 0xffff) + (pre_sum >> 16)


def _collate_bytes(msb, lsb):
    """
    Helper function for our helper functions.
    Collates msb and lsb into one 16-bit value.

    :type msb: str
    :param msb: Single byte (most significant).

    :type lsb: str
    :param lsb: Single byte (least significant).

    :return: msb and lsb all together in one 16 bit value.
    """
    return (ord(msb) << 8) + ord(lsb)


def ipv4_checksum(msg):
    """
    Return IPv4 checksum of msg.
    :param msg: Message to compute checksum over.
    :type msg: str

    :return: IPv4 checksum of msg.
    :rtype: int
    """
    # Pad with 0 byte if needed
    if len(msg) % 2 == 1:
        msg += "\x00"

    msg_words = map(_collate_bytes, msg[0::2], msg[1::2])
    total = reduce(_ones_complement_sum_carry_16, msg_words, 0)
    return ~total & 0xffff


def udp_checksum(msg, src_addr, dst_addr):
    """
    Return UDP checksum of msg.

    If msg is too big, the checksum is undefined, and this method will
    truncate it for the sake of checksum calculation. Note that this means the
    checksum will be invalid. This loosey goosey error checking is done to
    support fuzz tests which at times generate huge, invalid packets.


    :param msg: Message to compute checksum over.
    :type msg: str

    :return: UDP checksum of msg.
    :rtype: int
    """
    # If the packet is too big, the checksum is undefined since len(msg)
    # won't fit into two bytes. So we just pick our best definition.
    # "Truncate" the message as it appears in the checksum.
    msg = msg[0:ip_constants.UDP_MAX_LENGTH]

    # Construct pseudo header:
    data = src_addr + dst_addr + "\x00" + chr(ip_constants.IPV4_PROTOCOL_UDP) + struct.pack(">H", len(msg)) + msg

    # Pad with 0 byte if needed
    if len(data) % 2 == 1:
        data += "\x00"

    msg_words = map(_collate_bytes, data[0::2], data[1::2])
    total = reduce(_ones_complement_sum_carry_16, msg_words, 0)
    return ~total & 0xffff


def hex_str(s):
    """
    Returns a hex-formatted string based on s.
    :param s: Some string.
    :type s: str

    :return: Hex-formatted string representing s.
    :rtype: str
    """
    return ' '.join("{:02x}".format(ord(b)) for b in s)


def pause_for_signal():
    """
    Pauses the current thread in a way that can still receive signals like SIGINT from Ctrl+C.

    Implementation notes:
     - Linux uses signal.pause()
     - Windows uses a loop that sleeps for 1 ms at a time, allowing signals
       to interrupt the thread fairly quickly.

    :return: None
    :rtype: None
    """
    try:
        while True:
            signal.pause()
    except AttributeError:
        # signal.pause() is missing for Windows; wait 1ms and loop instead
        while True:
            time.sleep(0.001)
