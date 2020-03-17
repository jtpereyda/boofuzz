import os
import shutil
import unittest

import pytest
from past.builtins import xrange

from boofuzz import *


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestPrimitives(unittest.TestCase):
    def test_signed(self):
        s_initialize("UNIT TEST 1")
        s_byte(0, output_format="ascii", signed=True, name="byte_1")
        s_byte(0xFF // 2, output_format="ascii", signed=True, name="byte_2")
        s_byte(0xFF // 2 + 1, output_format="ascii", signed=True, name="byte_3")
        s_byte(0xFF, output_format="ascii", signed=True, name="byte_4")

        s_word(0, output_format="ascii", signed=True, name="word_1")
        s_word(0xFFFF // 2, output_format="ascii", signed=True, name="word_2")
        s_word(0xFFFF // 2 + 1, output_format="ascii", signed=True, name="word_3")
        s_word(0xFFFF, output_format="ascii", signed=True, name="word_4")

        s_dword(0, output_format="ascii", signed=True, name="dword_1")
        s_dword(0xFFFFFFFF // 2, output_format="ascii", signed=True, name="dword_2")
        s_dword(0xFFFFFFFF // 2 + 1, output_format="ascii", signed=True, name="dword_3")
        s_dword(0xFFFFFFFF, output_format="ascii", signed=True, name="dword_4")

        s_qword(0, output_format="ascii", signed=True, name="qword_1")
        s_qword(0xFFFFFFFFFFFFFFFF // 2, output_format="ascii", signed=True, name="qword_2")
        s_qword(0xFFFFFFFFFFFFFFFF // 2 + 1, output_format="ascii", signed=True, name="qword_3")
        s_qword(0xFFFFFFFFFFFFFFFF, output_format="ascii", signed=True, name="qword_4")

        req = s_get("UNIT TEST 1")

        self.assertEqual(req.names["byte_1"].render(), b"0")
        self.assertEqual(req.names["byte_2"].render(), b"127")
        self.assertEqual(req.names["byte_3"].render(), b"-128")
        self.assertEqual(req.names["byte_4"].render(), b"-1")
        self.assertEqual(req.names["word_1"].render(), b"0")
        self.assertEqual(req.names["word_2"].render(), b"32767")
        self.assertEqual(req.names["word_3"].render(), b"-32768")
        self.assertEqual(req.names["word_4"].render(), b"-1")
        self.assertEqual(req.names["dword_1"].render(), b"0")
        self.assertEqual(req.names["dword_2"].render(), b"2147483647")
        self.assertEqual(req.names["dword_3"].render(), b"-2147483648")
        self.assertEqual(req.names["dword_4"].render(), b"-1")
        self.assertEqual(req.names["qword_1"].render(), b"0")
        self.assertEqual(req.names["qword_2"].render(), b"9223372036854775807")
        self.assertEqual(req.names["qword_3"].render(), b"-9223372036854775808")
        self.assertEqual(req.names["qword_4"].render(), b"-1")

    def test_string(self):
        s_initialize("STRING UNIT TEST 1")
        s_string("foo", size=200, name="sized_string")

        req = s_get("STRING UNIT TEST 1")

        self.assertEqual(len(req.names["sized_string"].render()), 200)

        # check that string padding and truncation are working correctly.
        for i in xrange(0, 50):
            s_mutate()
            self.assertEqual(len(req.names["sized_string"].render()), 200)

    def test_s_mirror(self):
        test_group_values = [b"a", b"bb", b"ccc", b"dddd"]
        s_initialize("test_s_mirror")

        s_size("data", output_format="ascii", fuzzable=False, name="size")
        s_mirror("size", name="size_mirror")

        with s_block("data"):
            s_static("<")
            s_group("group_start", values=test_group_values)
            s_static(">")
            s_static("hello")
            s_static("</")
            s_mirror("group_start", name="group_end")
            s_static(">")

        req = s_get("test_s_mirror")
        for _ in xrange(len(test_group_values)):
            s_mutate()
            group_start_value = req.names["group_start"].render()
            self.assertEqual(
                int(req.names["size"].render()), len("<{0}>hello</{0}>".format(group_start_value.decode("utf-8")))
            )
            self.assertEqual(req.names["group_end"].render(), group_start_value)
            self.assertEqual(req.names["size_mirror"].render(), req.names["size"].render())

    def test_bytes(self):
        # test if s_bytes works with empty input
        s_initialize("test_bytes_empty")
        s_bytes(b"", name="bytes_empty")
        req = s_get("test_bytes_empty")
        while s_mutate():
            req.names["bytes_empty"].render()

        # test if max_len works
        s_initialize("test_bytes_max_len")
        s_bytes(b"12345", name="bytes_max_len", max_len=5)
        req = s_get("test_bytes_max_len")
        while s_mutate():
            self.assertLessEqual(len(req.names["bytes_max_len"].render()), 5)

        # test if size works
        s_initialize("test_bytes_size")
        s_bytes(b"1234567", name="bytes_size", size=7, padding=b"A")
        req = s_get("test_bytes_size")
        while s_mutate():
            self.assertEqual(len(req.names["bytes_size"].render()), 7)

        # test if fuzzable works
        s_initialize("test_bytes_fuzzable")
        s_bytes(b"1234567", name="bytes_fuzzable", fuzzable=False)
        s_get("test_bytes_fuzzable")
        self.assertFalse(s_mutate())

    @pytest.mark.skip(reason="Feature not implemented")
    def test_fuzz_extension(self):
        fuzz_strings_path = os.path.join(os.path.dirname(__file__), os.pardir, ".fuzz_strings")
        fuzz_ints_path = os.path.join(os.path.dirname(__file__), os.pardir, ".fuzz_ints")

        # backup existing fuzz extension libraries.
        try:
            shutil.move(fuzz_strings_path, fuzz_strings_path + "_backup")
            shutil.move(fuzz_ints_path, fuzz_ints_path + "_backup")
        except FileNotFoundError:
            pass

        # create extension libraries for unit test.
        with open(fuzz_strings_path, "w") as fh:
            fh.write("pedram\n")
            fh.write("amini\n")

        with open(fuzz_ints_path, "w") as fh:
            fh.write("deadbeef\n")
            fh.write("0xc0cac01a\n")

        s_initialize("EXTENSION TEST")

        s_string("foo", name="string")
        s_int(200, name="int")
        s_char(ord("A"), name="char")

        req = s_get("EXTENSION TEST")

        # restore existing fuzz extension libraries.
        try:
            shutil.move(fuzz_strings_path + "_backup", fuzz_strings_path)
            shutil.move(fuzz_ints_path + "_backup", fuzz_ints_path)
        except FileNotFoundError:
            os.remove(fuzz_strings_path)
            os.remove(fuzz_ints_path)

        # these should be here now.
        self.assertIn("pedram", req.names["string"]._fuzz_library)
        self.assertIn("amini", req.names["string"]._fuzz_library)
        self.assertIn(0xDEADBEEF, req.names["int"]._fuzz_library)
        self.assertIn(0xC0CAC01A, req.names["int"]._fuzz_library)

        # these should not as a char is too small to store them.
        self.assertNotIn(0xDEADBEEF, req.names["char"]._fuzz_library)
        self.assertNotIn(0xC0CAC01A, req.names["char"]._fuzz_library)


if __name__ == "__main__":
    unittest.main()
