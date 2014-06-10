from sulley import *

from struct import *

# stupid one byte XOR
def mcafee_epo_xor (buf, poly=0xAA):
    l = len(buf)
    new_buf = ""

    for char in buf:
        new_buf += chr(ord(char) ^ poly)

    return new_buf

########################################################################################################################
s_initialize("mcafee_epo_framework_tcp")
"""
    McAfee FrameworkService.exe TCP port 8081
"""

s_static("POST", name="post_verb")
s_delim(" ")
s_group("paths", ["/spipe/pkg", "/spipe/file", "default.htm"])
s_delim("?")
s_string("URL")
s_delim("=")
s_string("TESTFILE")
s_delim("\r\n")

s_static("Content-Length:")
s_delim(" ")
s_size("payload", format="ascii")
s_delim("\r\n\r\n")

if s_block_start("payload"):
    s_string("TESTCONTENTS")
    s_delim("\r\n")
s_block_end()


########################################################################################################################
s_initialize("mcafee_epo_framework_udp")
"""
    McAfee FrameworkService.exe UDP port 8082
"""

s_static('Type=\"AgentWakeup\"', name="agent_wakeup")
s_static('\"DataSize=\"')
s_size("data", format="ascii") # must be over 234

if s_block_start("data", encoder=mcafee_epo_xor):
    s_static("\x50\x4f", name="signature")
    s_group(values=[pack('<L', 0x40000001), pack('<L', 0x30000001), pack('<L', 0x20000001)], name="opcode")
    s_size("data", length=4) #TODO: needs to be size of data - 1 !!!

    s_string("size", size=210)
    s_static("EPO\x00")
    s_dword(1, name="other_opcode")

s_block_end()

########################################################################################################################
s_initialize("network_agent_udp")
"""
    McAfee Network Agent UDP/TCP port 6646
"""

s_size("kit_and_kaboodle", endian='>', fuzzable=True)

if s_block_start("kit_and_kaboodle"):
    # TODO: command? might want to fuzz this later.
    s_static("\x00\x00\x00\x02")
    
    # dunno what this is.
    s_static("\x00\x00\x00\x00")
    
    # here comes the first tag.
    s_static("\x00\x00\x00\x01")

    s_size("first_tag", endian='>', fuzzable=True)
    if s_block_start("first_tag"):
        s_string("McNAUniqueId", encoding="utf-16-le")
    s_block_end()

    # here comes the second tag.
    s_static("\x0b\x00\x00\x00")
    
    s_size("second_tag", fuzzable=True)
    if s_block_start("second_tag"):
        s_string("babee6e9-1cba-45be-9c81-05a3fb486ed7")
    s_block_end()
s_block_end()