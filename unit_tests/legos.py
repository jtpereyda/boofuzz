from boofuzz import *


def run():
    tag()
    ndr_string()
    # ber()

    # clear out the requests.
    blocks.REQUESTS = {}
    blocks.CURRENT = None


def tag():
    s_initialize("UNIT TEST TAG 1")
    s_lego("tag", value="pedram")

    req = s_get("UNIT TEST TAG 1")

    print "LEGO MUTATION COUNTS:"
    print "\ttag:    %d" % req.num_mutations()


def ndr_string():
    s_initialize("UNIT TEST NDR 1")
    s_lego("ndr_string", value="pedram")

    req = s_get("UNIT TEST NDR 1")
    # TODO: unfinished!
    # print req.render()


def ber():
    s_initialize("UNIT TEST BER 1")
    s_lego("ber_string", value="pedram")
    req = s_get("UNIT TEST BER 1")
    assert (s_render() == "\x04\x84\x00\x00\x00\x06\x70\x65\x64\x72\x61\x6d")
    s_mutate()
    assert (s_render() == "\x04\x84\x00\x00\x00\x00\x70\x65\x64\x72\x61\x6d")

    s_initialize("UNIT TEST BER 2")
    s_lego("ber_integer", value=0xdeadbeef)
    req = s_get("UNIT TEST BER 2")
    assert (s_render() == "\x02\x04\xde\xad\xbe\xef")
    s_mutate()
    assert (s_render() == "\x02\x04\x00\x00\x00\x00")
    s_mutate()
    assert (s_render() == "\x02\x04\x00\x00\x00\x01")