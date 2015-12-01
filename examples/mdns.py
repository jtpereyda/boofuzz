#!/usr/bin/python

# A partial MDNS fuzzer.  Could be made to be a DNS fuzzer trivially
# Charlie Miller <cmiller@securityevaluators.com>

from boofuzz import s_word, \
    s_initialize,          \
    sessions,              \
    s_block_start,         \
    s_size,                \
    s_block_end,           \
    s_string,              \
    s_repeat,              \
    s_group,               \
    s_dword,               \
    s_binary,              \
    s_get


def insert_questions(sess, node, edge, sock):
    node.names['Questions'].value = 1 + node.names['queries'].current_reps
    node.names['Authority'].value = 1 + node.names['auth_nameservers'].current_reps

s_initialize("query")
s_word(0, name="TransactionID")
s_word(0, name="Flags")
s_word(1, name="Questions", endian='>')
s_word(0, name="Answer", endian='>')
s_word(1, name="Authority", endian='>')
s_word(0, name="Additional", endian='>')

# ######## Queries ################
if s_block_start("query"):
    if s_block_start("name_chunk"):
        s_size("string", length=1)
        if s_block_start("string"):
            s_string("A" * 10)
        s_block_end()
    s_block_end()
    s_repeat("name_chunk", min_reps=2, max_reps=4, step=1, fuzzable=True, name="aName")

    s_group("end", values=["\x00", "\xc0\xb0"])  # very limited pointer fuzzing
    s_word(0xc, name="Type", endian='>')
    s_word(0x8001, name="Class", endian='>')
s_block_end()
s_repeat("query", 0, 1000, 40, name="queries")


######## Authorities ############
if s_block_start("auth_nameserver"):
    if s_block_start("name_chunk_auth"):
        s_size("string_auth", length=1)
        if s_block_start("string_auth"):
            s_string("A" * 10)
        s_block_end()
    s_block_end()
    s_repeat("name_chunk_auth", min_reps=2, max_reps=4, step=1, fuzzable=True, name="aName_auth")
    s_group("end_auth", values=["\x00", "\xc0\xb0"])  # very limited pointer fuzzing

    s_word(0xc, name="Type_auth", endian='>')
    s_word(0x8001, name="Class_auth", endian='>')
    s_dword(0x78, name="TTL_auth", endian='>')
    s_size("data_length", length=2, endian='>')
    if s_block_start("data_length"):
        s_binary("00 00 00 00 00 16 c0 b0")  # This should be fuzzed according to the type, but I'm too lazy atm
    s_block_end()
s_block_end()
s_repeat("auth_nameserver", 0, 1000, 40, name="auth_nameservers")

s_word(0)

sess = sessions.Session(proto="udp")
target = sessions.Target("224.0.0.251", 5353)
sess.add_target(target)
sess.connect(s_get("query"), callback=insert_questions)

sess.fuzz()

