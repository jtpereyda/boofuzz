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

        n = 0
        for expected, actual in zip(b._fuzz_library, generator):
            n += 1
            self.assertEqual(expected, actual)
        for expected, actual in zip(b._mutators_of_default_value, generator):
            n += 1
            self.assertEqual(expected(default_value), actual(default_value))
        for expected, actual in zip(b._magic_debug_values, generator):
            n += 1
            self.assertEqual(expected, actual)
        for i in range(0, len(default_default_value)):
            for expected_fuzz_string in b._fuzz_strings_1byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 1 :]
                self.assertEqual(expected_value, actual_value)
        for i in range(0, len(default_default_value) - 1):
            for expected_fuzz_string in b._fuzz_strings_2byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 2 :]
                self.assertEqual(expected_value, actual_value)
        for i in range(0, len(default_default_value) - 3):
            for expected_fuzz_string in b._fuzz_strings_4byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 4 :]
                self.assertEqual(expected_value, actual_value)

        self.assertEqual(n, b.num_mutations(default_value=default_value))

    def test_mutations_max_len(self):
        max_len = 7

        def truncate(b):
            return b[0:max_len]

        default_value = b"ABCDEFGH"
        default_default_value = b"\x00" * len(default_value)
        b = Bytes(max_len=max_len)
        generator = b.mutations(default_value=default_default_value)

        n = 0
        for expected, actual in zip(map(truncate, b._fuzz_library), generator):
            n += 1
            self.assertEqual(expected, actual)
        for expected, actual in zip(b._mutators_of_default_value, generator):
            n += 1
            self.assertEqual(truncate(expected(default_value)), actual(default_value))
        for expected, actual in zip(map(truncate, b._magic_debug_values), generator):
            n += 1
            self.assertEqual(expected, actual)
        for i in range(0, len(default_default_value)):
            for expected_fuzz_string in b._fuzz_strings_1byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 1 :]
                self.assertEqual(truncate(expected_value), actual_value)
        for i in range(0, len(default_default_value) - 1):
            for expected_fuzz_string in b._fuzz_strings_2byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 2 :]
                self.assertEqual(truncate(expected_value), actual_value)
        for i in range(0, len(default_default_value) - 3):
            for expected_fuzz_string in b._fuzz_strings_4byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 4 :]
                self.assertEqual(truncate(expected_value), actual_value)

        self.assertEqual(n, b.num_mutations(default_value=default_value))

    def test_mutations_size(self):
        size = 5
        pad = b"\x41"

        def fit_to_size(b):
            fullpad = b"\x41" * 5
            pad_len = max(0, size - len(b))
            return b[0:size] + fullpad[0:pad_len]

        default_value = b"ABCDEFGH"
        default_default_value = b"\x00" * len(default_value)
        b = Bytes(size=size, padding=pad)
        generator = b.mutations(default_value=default_default_value)

        n = 0
        for expected, actual in zip(map(fit_to_size, b._fuzz_library), generator):
            n += 1
            self.assertEqual(expected, actual)
        for expected, actual in zip(b._mutators_of_default_value, generator):
            n += 1
            self.assertEqual(fit_to_size(expected(default_value)), actual(default_value))
        for expected, actual in zip(map(fit_to_size, b._magic_debug_values), generator):
            n += 1
            self.assertEqual(expected, actual)
        for i in range(0, len(default_default_value)):
            for expected_fuzz_string in b._fuzz_strings_1byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 1 :]
                self.assertEqual(fit_to_size(expected_value), actual_value)
        for i in range(0, len(default_default_value) - 1):
            for expected_fuzz_string in b._fuzz_strings_2byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 2 :]
                self.assertEqual(fit_to_size(expected_value), actual_value)
        for i in range(0, len(default_default_value) - 3):
            for expected_fuzz_string in b._fuzz_strings_4byte:
                n += 1
                actual_callable = next(generator)
                actual_value = actual_callable(default_value)
                expected_value = default_value[0:i] + expected_fuzz_string + default_value[i + 4 :]
                self.assertEqual(fit_to_size(expected_value), actual_value)

        self.assertEqual(n, b.num_mutations(default_value=default_value))


if __name__ == "__main__":
    unittest.main()
