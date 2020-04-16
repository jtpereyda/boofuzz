import unittest

import pytest

from boofuzz import *


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestBytes(unittest.TestCase):
    def test_mutations(self):
        default_value = b"ABCDEFGH"
        default_default_value = b"\x00" * len(default_value)
        b = Bytes()
        generator = b.mutations(default_value=default_default_value)
        for expected, actual in zip(b._fuzz_library, generator):
            self.assertEqual(expected, actual)
        for expected, actual in zip(b._mutators_of_default_value, generator):
            # print("{0} --- {1}".format(expected,actual))
            self.assertEqual(expected(default_value), actual(default_value))
        for expected, actual in zip(b._magic_debug_values, generator):
            self.assertEqual(expected, actual)
        for i in range(0, len(default_default_value)):
            for expected_fuzz_string in b._fuzz_strings_1byte:
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 1 :]
                self.assertEqual(expected_value, actual_value)


if __name__ == "__main__":
    unittest.main()
