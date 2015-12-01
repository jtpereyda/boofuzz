from boofuzz import *


s_initialize("trillian 1")

s_static("\x00\x00")  # transaction ID
s_static("\x00\x00")  # flags (standard query)
s_word(1, endian=">")  # number of questions
s_word(0, endian=">", fuzzable=False)  # answer RRs
s_word(0, endian=">", fuzzable=False)  # authority RRs
s_word(0, endian=">", fuzzable=False)  # additional RRs

# queries
s_lego("dns_hostname", "_presence._tcp.local")
s_word(0x000c, endian=">")  # type  = pointer
s_word(0x8001, endian=">")  # class = flush

s_initialize("trillian 2")

if s_block_start("pamini.local"):
    if s_block_start("header"):
        s_static("\x00\x00")  # transaction ID
        s_static("\x00\x00")  # flags (standard query)
        s_word(2, endian=">")  # number of questions
        s_word(0, endian=">", fuzzable=False)  # answer RRs
        s_word(2, endian=">", fuzzable=False)  # authority RRs
        s_word(0, endian=">", fuzzable=False)  # additional RRs
    s_block_end()

    # queries
    s_lego("dns_hostname", "pamini.local")
    s_word(0x00ff, endian=">")  # type  = any
    s_word(0x8001, endian=">")  # class = flush
s_block_end()

s_lego("dns_hostname", "pedram@PAMINI._presence._tcp")
s_word(0x00ff, endian=">")  # type  = any
s_word(0x8001, endian=">")  # class = flush


# authoritative nameservers
s_static("\xc0")  # offset specifier
s_size("header", length=1)  # offset to pamini.local
s_static("\x00\x01")  # type  = A (host address)
s_static("\x00\x01")  # class = in
s_static("\x00\x00\x00\xf0")  # ttl 4 minutes
s_static("\x00\x04")  # data length
s_static(chr(152) + chr(67) + chr(137) + chr(53))  # ip address

s_static("\xc0")  # offset specifier
s_size("pamini.local", length=1)  # offset to pedram@PAMINI...
s_static("\x00\x21")  # type  = SRV (service location)
s_static("\x00\x01")  # class = in
s_static("\x00\x00\x00\xf0")  # ttl 4 minutes
s_static("\x00\x08")  # data length
s_static("\x00\x00")  # priority
s_static("\x00\x00")  # weight
s_static("\x14\xb2")  # port
s_static("\xc0")  # offset specifier
s_size("header", length=1)  # offset to pamini.local

s_initialize("trillian 3")

if s_block_start("pamini.local"):
    if s_block_start("header"):
        s_static("\x00\x00")  # transaction ID
        s_static("\x00\x00")  # flags (standard query)
        s_word(2, endian=">")  # number of questions
        s_word(0, endian=">", fuzzable=False)  # answer RRs
        s_word(2, endian=">", fuzzable=False)  # authority RRs
        s_word(0, endian=">", fuzzable=False)  # additional RRs
    s_block_end()

    # queries
    s_lego("dns_hostname", "pamini.local")
    s_word(0x00ff, endian=">")  # type  = any
    s_word(0x0001, endian=">")  # class = in
s_block_end()

s_lego("dns_hostname", "pedram@PAMINI._presence._tcp")
s_word(0x00ff, endian=">")  # type  = any
s_word(0x0001, endian=">")  # class = in


# authoritative nameservers
s_static("\xc0")  # offset specifier
s_size("header", length=1)  # offset to pamini.local
s_static("\x00\x01")  # type  = A (host address)
s_static("\x00\x01")  # class = in
s_static("\x00\x00\x00\xf0")  # ttl 4 minutes
s_static("\x00\x04")  # data length
s_static(chr(152) + chr(67) + chr(137) + chr(53))  # ip address

s_static("\xc0")  # offset specifier
s_size("pamini.local", length=1)  # offset to pedram@PAMINI...
s_static("\x00\x21")  # type  = SRV (service location)
s_static("\x00\x01")  # class = in
s_static("\x00\x00\x00\xf0")  # ttl 4 minutes
s_static("\x00\x08")  # data length
s_static("\x00\x00")  # priority
s_static("\x00\x00")  # weight
s_static("\x14\xb2")  # port
s_static("\xc0")  # offset specifier
s_size("header", length=1)  # offset to pamini.local