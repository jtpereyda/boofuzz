from sulley import *

from struct import *


########################################################################################################################
def unicode_ftw(val):
    """
    Simple unicode slicer
    """

    val_list = []
    for char in val:
        val_list.append("\x00")
        val_list.append(pack('B', ord(char)))

    ret = ""
    for char in val_list:
        ret += char

    return ret

########################################################################################################################
s_initialize("omni")
"""
    Hewlett Packard OpenView Data Protector OmniInet.exe
"""


if s_block_start("packet_1"):
    s_size("packet_2", endian=">", length=4)
s_block_end()

if s_block_start("packet_2"):

    # unicode byte order marker
    s_static("\xfe\xff")

    # unicode magic
    if s_block_start("unicode_magic", encoder=unicode_ftw):
        s_int(267, format="ascii")
    s_block_end()
    s_static("\x00\x00")

    # random 2 bytes
    s_string("AA", size=2)

    # unicode value to pass calls to wtoi()
    if s_block_start("unicode_100_1", encoder=unicode_ftw):
        s_int(100, format="ascii")
    s_block_end()
    s_static("\x00\x00")

    # random 2 bytes
    s_string("BB", size=2)

    # unicode value to pass calls to wtoi()
    if s_block_start("unicode_100_2", encoder=unicode_ftw):
        s_int(100, format="ascii")
    s_block_end()
    s_static("\x00\x00")

    # random 2 bytes
    s_string("CC", size=2)

    # unicode value to pass calls to wtoi()
    if s_block_start("unicode_100_3", encoder=unicode_ftw):
        s_int(100, format="ascii")
    s_block_end()
    s_static("\x00\x00")

    # random buffer
    s_string("D"*32, size=32)

    # barhost cookie
    s_dword(0x7cde7bab, endian="<", fuzzable=False)

    # random buffer
    s_string("FOO")

s_block_end()
