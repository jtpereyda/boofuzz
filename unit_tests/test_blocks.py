import unittest

import pytest

from boofuzz import *


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestBlocks(unittest.TestCase):
    def test_groups_and_num_cases(self):
        s_initialize("UNIT TEST 1")
        s_size("BLOCK", length=4, name="sizer")
        s_group("group", values=[b"\x01", b"\x05", b"\x0a", b"\xff"])
        if s_block_start("BLOCK"):
            s_delim(">", name="delim")
            s_string("pedram", name="string")
            s_byte(0xDE, name="byte")
            s_word(0xDEAD, name="word")
            s_dword(0xDEADBEEF, name="dword")
            s_qword(0xDEADBEEFDEADBEEF, name="qword")
            s_random(0, 5, 10, 100, name="random")
            s_block_end()

        # count how many mutations we get per primitive type.
        req1 = s_get("UNIT TEST 1")
        print("PRIMITIVE MUTATION COUNTS (SIZES):")

        print(
            "\tdelim:  %d\t(%s)"
            % (req1.names["delim"].num_mutations(), sum(map(len, req1.names["delim"]._fuzz_library)))
        )

        print(
            "\tstring: %d\t(%s)"
            % (req1.names["string"].num_mutations(), sum(map(len, req1.names["string"]._fuzz_library)))
        )

        print("\tbyte:   %d" % req1.names["byte"].num_mutations())
        print("\tword:   %d" % req1.names["word"].num_mutations())
        print("\tdword:  %d" % req1.names["dword"].num_mutations())
        print("\tqword:  %d" % req1.names["qword"].num_mutations())
        print("\tsizer:  %d" % req1.names["sizer"].num_mutations())

        # we specify the number of mutations in a random field, so ensure that matches.
        self.assertEqual(req1.names["random"].num_mutations(), 100)

        # we specify the number of values in a group field, so ensure that matches.
        self.assertEqual(req1.names["group"].num_mutations(), 4)

        # assert that the number of block mutations equals the sum of the number of mutations of its components.
        self.assertEqual(
            req1.names["BLOCK"].num_mutations(),
            req1.names["delim"].num_mutations()
            + req1.names["string"].num_mutations()
            + req1.names["byte"].num_mutations()
            + req1.names["word"].num_mutations()
            + req1.names["dword"].num_mutations()
            + req1.names["qword"].num_mutations()
            + req1.names["random"].num_mutations(),
        )

        s_initialize("UNIT TEST 2")
        s_group("group", values=[b"\x01", b"\x05", b"\x0a", b"\xff"])
        if s_block_start("BLOCK", group="group"):
            s_delim(">", name="delim")
            s_string("pedram", name="string")
            s_byte(0xDE, name="byte")
            s_word(0xDEAD, name="word")
            s_dword(0xDEADBEEF, name="dword")
            s_qword(0xDEADBEEFDEADBEEF, name="qword")
            s_random(0, 5, 10, 100, name="random")
            s_block_end()

        # assert that the number of block mutations in request 2 is len(group.values) (4) times that of request 1.
        req2 = s_get("UNIT TEST 2")
        self.assertEqual(req2.names["BLOCK"].num_mutations(), req1.names["BLOCK"].num_mutations() * 4)

    def test_dependencies(self):
        s_initialize("DEP TEST 1")
        s_group("group", values=[b"1", b"2"])

        if s_block_start("ONE", dep="group", dep_values=["1"]):
            s_static("ONE" * 100)
            s_block_end()

        if s_block_start("TWO", dep="group", dep_values=["2"]):
            s_static("TWO" * 100)
            s_block_end()

        self.assertEqual(s_num_mutations(), 2)
        self.assertTrue(s_mutate())
        self.assertEqual(s_render().find(b"TWO"), -1)
        self.assertTrue(s_mutate())
        self.assertEqual(s_render().find(b"ONE"), -1)
        self.assertFalse(s_mutate())

    def test_repeaters(self):
        s_initialize("REP TEST 1")
        if s_block_start("BLOCK"):
            s_delim(">", name="delim", fuzzable=False)
            s_string("pedram", name="string", fuzzable=False)
            s_byte(0xDE, name="byte", fuzzable=False)
            s_word(0xDEAD, name="word", fuzzable=False)
            s_dword(0xDEADBEEF, name="dword", fuzzable=False)
            s_qword(0xDEADBEEFDEADBEEF, name="qword", fuzzable=False)
            s_random("0", 5, 10, 100, name="random", fuzzable=False)
            s_block_end()
        s_repeat("BLOCK", min_reps=5, max_reps=15, step=5)

        data = s_render()
        length = len(data)

        s_mutate()
        data = s_render()
        self.assertEqual(len(data), length + length * 5)

        s_mutate()
        data = s_render()
        self.assertEqual(len(data), length + length * 10)

        s_mutate()
        data = s_render()
        self.assertEqual(len(data), length + length * 15)

        s_mutate()
        data = s_render()
        self.assertEqual(len(data), length)

    def test_return_current_mutant(self):
        s_initialize("RETURN CURRENT MUTANT TEST 1")

        s_dword(0xDEADBEEF, name="boss hog")
        s_string("bloodhound gang", name="vagina")

        if s_block_start("BLOCK1"):
            s_string("foo", name="foo")
            s_string("bar", name="bar")
            s_dword(0x20)
        s_block_end()

        s_dword(0xDEAD)
        s_dword(0x0FED)

        s_string("sucka free at 2 in morning 7/18", name="uhntiss")

        req1 = s_get("RETURN CURRENT MUTANT TEST 1")

        # calculate the length of the mutation libraries dynamically since they may change with time.
        num_str_mutations = req1.names["foo"].num_mutations()
        num_int_mutations = req1.names["boss hog"].num_mutations()

        for i in range(num_str_mutations + num_int_mutations - 10):
            req1.mutate()

        self.assertEqual(req1.mutant.name, "vagina")
        req1.reset()

        for i in range(num_int_mutations + num_str_mutations + 1):
            req1.mutate()
        self.assertEqual(req1.mutant.name, "foo")
        req1.reset()

        for i in range(num_str_mutations * 2 + num_int_mutations + 1):
            req1.mutate()
        self.assertEqual(req1.mutant.name, "bar")
        req1.reset()

        for i in range(num_str_mutations * 3 + num_int_mutations * 4 + 1):
            req1.mutate()
        self.assertEqual(req1.mutant.name, "uhntiss")
        req1.reset()

    def test_with_statements(self):
        s_initialize("WITH TEST")

        with s_block("BLOCK1") as b:
            self.assertEqual(b.name, "BLOCK1")
            s_static("test")

        req = s_get("WITH TEST")
        self.assertEqual(req.num_mutations(), 0)
        self.assertEqual(req.render(), b"test")

    def test_skip_element(self):
        s_initialize("SKIP TEST")

        with s_block("BLOCK1"):
            s_string("foo", name="foo")
            s_string("bar", name="bar")
        s_string("baz", name="baz")

        req = s_get("SKIP TEST")
        req.mutate()
        self.assertEqual(req.mutant.name, "foo")
        req.skip_element()
        req.mutate()
        self.assertEqual(req.mutant.name, "bar")
        req.skip_element()
        req.mutate()
        self.assertEqual(req.mutant.name, "baz")


if __name__ == "__main__":
    unittest.main()
