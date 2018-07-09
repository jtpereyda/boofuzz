from boofuzz import *


def run():
    groups_and_num_test_cases()
    dependencies()
    repeaters()
    return_current_mutant()
    with_statements()

    # clear out the requests.
    blocks.REQUESTS = {}
    blocks.CURRENT = None


def groups_and_num_test_cases():
    s_initialize("UNIT TEST 1")
    s_size("BLOCK", length=4, name="sizer")
    s_group("group", values=["\x01", "\x05", "\x0a", "\xff"])
    if s_block_start("BLOCK"):
        s_delim(">", name="delim")
        s_string("pedram", name="string")
        s_byte(0xde, name="byte")
        s_word(0xdead, name="word")
        s_dword(0xdeadbeef, name="dword")
        s_qword(0xdeadbeefdeadbeef, name="qword")
        s_random(0, 5, 10, 100, name="random")
        s_block_end()

    # count how many mutations we get per primitive type.
    req1 = s_get("UNIT TEST 1")
    print "PRIMITIVE MUTATION COUNTS (SIZES):"

    print "\tdelim:  %d\t(%s)" % (
        req1.names["delim"].num_mutations(),
        sum(map(len, req1.names["delim"]._fuzz_library))
    )

    print "\tstring: %d\t(%s)" % (
        req1.names["string"].num_mutations(),
        sum(map(len, req1.names["string"]._fuzz_library))
    )

    print "\tbyte:   %d" % req1.names["byte"].num_mutations()
    print "\tword:   %d" % req1.names["word"].num_mutations()
    print "\tdword:  %d" % req1.names["dword"].num_mutations()
    print "\tqword:  %d" % req1.names["qword"].num_mutations()
    print "\tsizer:  %d" % req1.names["sizer"].num_mutations()

    # we specify the number of mutations in a random field, so ensure that matches.
    assert (req1.names["random"].num_mutations() == 100)

    # we specify the number of values in a group field, so ensure that matches.
    assert (req1.names["group"].num_mutations() == 4)

    # assert that the number of block mutations equals the sum of the number of mutations of its components.
    assert (req1.names["BLOCK"].num_mutations() == (
            req1.names["delim"].num_mutations() +
            req1.names["string"].num_mutations() +
            req1.names["byte"].num_mutations() +
            req1.names["word"].num_mutations() +
            req1.names["dword"].num_mutations() +
            req1.names["qword"].num_mutations() +
            req1.names["random"].num_mutations()
    ))

    s_initialize("UNIT TEST 2")
    s_group("group", values=["\x01", "\x05", "\x0a", "\xff"])
    if s_block_start("BLOCK", group="group"):
        s_delim(">", name="delim")
        s_string("pedram", name="string")
        s_byte(0xde, name="byte")
        s_word(0xdead, name="word")
        s_dword(0xdeadbeef, name="dword")
        s_qword(0xdeadbeefdeadbeef, name="qword")
        s_random(0, 5, 10, 100, name="random")
        s_block_end()

    # assert that the number of block mutations in request 2 is len(group.values) (4) times that of request 1.
    req2 = s_get("UNIT TEST 2")
    assert (req2.names["BLOCK"].num_mutations() == req1.names["BLOCK"].num_mutations() * 4)


def dependencies():
    s_initialize("DEP TEST 1")
    s_group("group", values=["1", "2"])

    if s_block_start("ONE", dep="group", dep_values=["1"]):
        s_static("ONE" * 100)
        s_block_end()

    if s_block_start("TWO", dep="group", dep_values=["2"]):
        s_static("TWO" * 100)
        s_block_end()

    assert (s_num_mutations() == 2)
    assert (s_mutate() == True)
    assert (s_render().find("TWO") == -1)
    assert (s_mutate() == True)
    assert (s_render().find("ONE") == -1)
    assert (s_mutate() == False)


def repeaters():
    s_initialize("REP TEST 1")
    if s_block_start("BLOCK"):
        s_delim(">", name="delim", fuzzable=False)
        s_string("pedram", name="string", fuzzable=False)
        s_byte(0xde, name="byte", fuzzable=False)
        s_word(0xdead, name="word", fuzzable=False)
        s_dword(0xdeadbeef, name="dword", fuzzable=False)
        s_qword(0xdeadbeefdeadbeef, name="qword", fuzzable=False)
        s_random(0, 5, 10, 100, name="random", fuzzable=False)
        s_block_end()
    s_repeat("BLOCK", min_reps=5, max_reps=15, step=5)

    data = s_render()
    length = len(data)

    s_mutate()
    data = s_render()
    assert (len(data) == length + length * 5)

    s_mutate()
    data = s_render()
    assert (len(data) == length + length * 10)

    s_mutate()
    data = s_render()
    assert (len(data) == length + length * 15)

    s_mutate()
    data = s_render()
    assert (len(data) == length)


def return_current_mutant():
    s_initialize("RETURN CURRENT MUTANT TEST 1")

    s_dword(0xdeadbeef, name="boss hog")
    s_string("bloodhound gang", name="vagina")

    if s_block_start("BLOCK1"):
        s_string("foo", name="foo")
        s_string("bar", name="bar")
        s_dword(0x20)
    s_block_end()

    s_dword(0xdead)
    s_dword(0x0fed)

    s_string("sucka free at 2 in morning 7/18", name="uhntiss")

    req1 = s_get("RETURN CURRENT MUTANT TEST 1")

    # calculate the length of the mutation libraries dynamically since they may change with time.
    num_str_mutations = req1.names["foo"].num_mutations()
    num_int_mutations = req1.names["boss hog"].num_mutations()

    for i in xrange(num_str_mutations + num_int_mutations - 10):
        req1.mutate()

    assert (req1.mutant.name == "vagina")
    req1.reset()

    for i in xrange(num_int_mutations + num_str_mutations + 1):
        req1.mutate()
    assert (req1.mutant.name == "foo")
    req1.reset()

    for i in xrange(num_str_mutations * 2 + num_int_mutations + 1):
        req1.mutate()
    assert (req1.mutant.name == "bar")
    req1.reset()

    for i in xrange(num_str_mutations * 3 + num_int_mutations * 4 + 1):
        req1.mutate()
    assert (req1.mutant.name == "uhntiss")
    req1.reset()


def with_statements():
    s_initialize("WITH TEST")

    with s_block("BLOCK1") as b:
        assert (b.name == "BLOCK1")
        s_static("test")

    req = s_get("WITH TEST")
    assert (req.num_mutations() == 0)
    assert (req.render() == "test")
