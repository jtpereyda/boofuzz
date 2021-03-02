import unittest

import pytest

from boofuzz import *
from boofuzz.mutation_context import MutationContext


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class DebuggableTestCase(unittest.TestCase):
    @classmethod
    def debugTestCase(cls):
        loader = unittest.defaultTestLoader
        testSuite = loader.loadTestsFromTestCase(cls)
        testSuite.debug()


class TestBlocks(DebuggableTestCase):
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
            s_random(b"\x00", 5, 10, 100, name="random")
            s_block_end()

        req1 = s_get("UNIT TEST 1")
        sizer = req1.resolve_name("BLOCK", "sizer")
        group = req1.resolve_name("", "group")
        block = req1.resolve_name("", "BLOCK")
        delim = req1.resolve_name("BLOCK", "delim")
        string = req1.resolve_name("BLOCK", "string")
        byte = req1.resolve_name("BLOCK", "byte")
        word = req1.resolve_name("BLOCK", "word")
        dword = req1.resolve_name("BLOCK", "dword")
        qword = req1.resolve_name("BLOCK", "qword")
        random = req1.resolve_name("BLOCK", "random")

        # count how many mutations we get per primitive type.
        print("PRIMITIVE MUTATION COUNTS (SIZES):")

        print("\tdelim:  %d\t(%s)" % (delim.get_num_mutations(), sum(map(len, delim._fuzz_library))))

        print("\tstring: %d\t(%s)" % (string.get_num_mutations(), sum(map(len, string._fuzz_library))))

        print("\tbyte:   %d" % byte.get_num_mutations())
        print("\tword:   %d" % word.get_num_mutations())
        print("\tdword:  %d" % dword.get_num_mutations())
        print("\tqword:  %d" % qword.get_num_mutations())
        print("\tsizer:  %d" % sizer.get_num_mutations())

        # we specify the number of mutations in a random field, so ensure that matches.
        self.assertEqual(random.get_num_mutations(), 100)

        # we specify the number of values in a group field, so ensure that matches.
        self.assertEqual(group.get_num_mutations(), 3)

        # assert that the number of block mutations equals the sum of the number of mutations of its components.
        self.assertEqual(
            block.get_num_mutations(),
            delim.get_num_mutations()
            + string.get_num_mutations()
            + byte.get_num_mutations()
            + word.get_num_mutations()
            + dword.get_num_mutations()
            + qword.get_num_mutations()
            + random.get_num_mutations(),
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
            s_random(b"\x00", 5, 10, 100, name="random")
            s_block_end()

        req2 = s_get("UNIT TEST 2")
        req2block = req2.resolve_name("", "BLOCK")

        self.assertEqual(req2block.get_num_mutations(), block.get_num_mutations() * 4)

    def test_dependencies(self):
        s_initialize("DEP TEST 1")
        s_group("group", default_value=b"0", values=[b"1", b"2"])

        if s_block_start("ONE", dep="group", dep_values=[b"1"]):
            s_static("ONE")
            s_block_end()

        if s_block_start("TWO", dep="group", dep_values=[b"2"]):
            s_static("TWO")
            s_group("group2", default_value=b"0", values=[b"1", b"2"])
            s_block_end()

        mutations = list(blocks.CURRENT.get_mutations())
        rendered = blocks.CURRENT.render()
        assert b"ONE" not in rendered
        assert b"TWO" not in rendered
        rendered = blocks.CURRENT.render(MutationContext(mutation=mutations[0]))
        assert b"ONE" in rendered
        assert b"TWO" not in rendered
        rendered = blocks.CURRENT.render(MutationContext(mutation=mutations[1]))
        assert b"ONE" not in rendered
        assert b"TWO" in rendered
        assert len(mutations) == 4

    def test_repeaters(self):
        s_initialize("REP TEST 1")
        if s_block_start("BLOCK"):
            s_delim(">", name="delim", fuzzable=False)
            s_string("pedram", name="string", fuzzable=False)
            s_byte(0xDE, name="byte", fuzzable=False)
            s_word(0xDEAD, name="word", fuzzable=False)
            s_dword(0xDEADBEEF, name="dword", fuzzable=False)
            s_qword(0xDEADBEEFDEADBEEF, name="qword", fuzzable=False)
            s_random(b"0", 5, 10, 100, name="random", fuzzable=False)
            s_block_end()
        s_repeat("BLOCK", min_reps=5, max_reps=15, step=5)

        data = blocks.CURRENT.render()
        length = len(data)
        self.assertEqual(23, length)

        expected_lengths = [length + length * 5, length + length * 10, length + length * 15]
        for mutation, expected_length in zip(blocks.CURRENT.get_mutations(), expected_lengths):
            data = blocks.CURRENT.render(MutationContext(mutation=mutation))
            self.assertEqual(expected_length, len(data))

    def test_return_current_mutant(self):
        s_initialize("RETURN CURRENT MUTANT TEST 1")

        s_dword(0xDEADBEEF, name="deadbeef")
        s_string("str1", name="asdf")

        if s_block_start("BLOCK1"):
            s_string("foo", name="foo")
            s_string("bar", name="bar")
            s_dword(0x20)
        s_block_end()

        s_dword(0xDEAD)
        s_dword(0x0FED)

        s_string("str2", name="findit")

        req1 = s_get("RETURN CURRENT MUTANT TEST 1")

        num_str_mutations = req1.names["RETURN CURRENT MUTANT TEST 1.BLOCK1.foo"].get_num_mutations()
        num_int_mutations = req1.names["RETURN CURRENT MUTANT TEST 1.deadbeef"].get_num_mutations()

        mutations_generator = req1.get_mutations()
        for _ in range(num_str_mutations + num_int_mutations - 10):
            next(mutations_generator)
        self.assertEqual(req1.mutant.name, "asdf")

        mutations_generator = req1.get_mutations()
        for _ in range(num_int_mutations + num_str_mutations + 1):
            next(mutations_generator)
        self.assertEqual(req1.mutant.name, "foo")

        mutations_generator = req1.get_mutations()
        for _ in range(num_str_mutations * 2 + num_int_mutations + 1):
            next(mutations_generator)
        self.assertEqual(req1.mutant.name, "bar")

        mutations_generator = req1.get_mutations()
        for _ in range(num_str_mutations * 3 + num_int_mutations * 4 + 1):
            next(mutations_generator)
        self.assertEqual(req1.mutant.name, "findit")

    def test_with_statements(self):
        s_initialize("WITH TEST")

        with s_block("BLOCK1") as b:
            self.assertEqual(b.name, "BLOCK1")
            s_static("test")

        req = s_get("WITH TEST")
        self.assertEqual(req.num_mutations(), 0)
        self.assertEqual(req.render(), b"test")


if __name__ == "__main__":
    TestBlocks.debugTestCase()
