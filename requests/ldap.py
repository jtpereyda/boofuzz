from sulley import *

"""
Application number	Application
0	BindRequest
1	BindResponse
2	UnbindRequest
3	SearchRequest
4	SearchResponse
5	ModifyRequest
6	ModifyResponse
7	AddRequest
8	AddResponse
9	DelRequest
10	DelResponse
11	ModifyRDNRequest
12	ModifyRDNResponse
13	CompareRequest
14	CompareResponse
15	AbandonRequest
"""

########################################################################################################################
s_initialize("anonymous bind")

# all ldap messages start with this.
s_static("\x30")

# length of entire envelope.
s_static("\x84")
s_sizer("envelope", endian=">")

if s_block_start("envelope"):
    s_static("\x02\x01\x01")        # message id (always one)
    s_static("\x60")                # bind request (0)

    s_static("\x84")
    s_sizer("bind request", endian=">")

    if s_block_start("bind request"):
        s_static("\x02\x01\x03")    # version

        s_lego("ber_string", "anonymous")
        s_lego("ber_string", "foobar", options={"prefix":"\x80"})   # 0x80 is "simple" authentication
    s_block_end()
s_block_end()


########################################################################################################################
s_initialize("search request")

# all ldap messages start with this.
s_static("\x30")

# length of entire envelope.
s_static("\x84")
s_sizer("envelope", endian=">", fuzzable=True)

if s_block_start("envelope"):
    s_static("\x02\x01\x02")        # message id (always one)
    s_static("\x63")                # search request (3)

    s_static("\x84")
    s_sizer("searchRequest", endian=">", fuzzable=True)

    if s_block_start("searchRequest"):
        s_static("\x04\x00")        # static empty string ... why?
        s_static("\x0a\x01\x00")    # scope: baseOjbect (0)
        s_static("\x0a\x01\x00")    # deref: never (0)
        s_lego("ber_integer", 1000) # size limit
        s_lego("ber_integer", 30)   # time limit
        s_static("\x01\x01\x00")    # typesonly: false
        s_lego("ber_string", "objectClass", options={"prefix":"\x87"})
        s_static("\x30")

        s_static("\x84")
        s_sizer("attributes", endian=">")

        if s_block_start("attributes"):
            s_lego("ber_string", "1.1")
        s_block_end("attributes")

    s_block_end("searchRequest")
s_block_end("envelope")