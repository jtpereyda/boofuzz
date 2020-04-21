import unittest

import pytest

from boofuzz import *


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestString(unittest.TestCase):
    def _given_string(self):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return String("boofuzz-unit-test-name", self.default_value)

    def _given_bytes_max_len(self, max_len):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return Bytes("boofuzz-unit-test-name", self.default_value, max_len=max_len)

    def _given_bytes_size(self, size, padding):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return Bytes("boofuzz-unit-test-name", self.default_value, size=size, padding=padding)

    def test_mutations(self):
        uut = self._given_string()

        generator = uut.mutations(default_value=self.default_default_value)

        n = 0
        for expected, actual in zip(String._fuzz_library, generator):
            n += 1
            self.assertEqual(expected, actual)

        for expected, actual in zip(String._variable_mutation_multipliers, generator):
            n += 1
            self.assertEqual(self.default_default_value * expected, actual)

        for sequence in String.long_string_seeds:
            for size in String._long_string_lengths:
                for delta in String._long_string_deltas:
                    n += 1
                    self.assertEqual(sequence * (size + delta), next(generator))

        for size in String._long_string_lengths:
            s = "D" * size
            for loc in uut.random_indices[size]:
                s = s[:loc] + "\x00" + s[loc:]
                n += 1
                self.assertEqual(s, next(generator))

        for sequence in String.long_string_seeds:
            for size in String._extra_long_string_lengths:
                n += 1
                self.assertEqual(sequence * size, next(generator))

        self.assertRaises(StopIteration, lambda: next(generator))
        self.assertEqual(n, uut.num_mutations(default_value=self.default_value))

    # def test_mutations_max_len(self):
    #     max_len = 7
    #     uut = self._given_bytes_max_len(max_len=max_len)
    #     generator = uut.mutations(default_value=self.default_default_value)
    #
    #     def truncate(b):
    #         return b[0:max_len]
    #
    #     n = 0
    #     for expected, actual in zip(map(truncate, uut._fuzz_library), generator):
    #         n += 1
    #         self.assertEqual(expected, actual)
    #     for expected, actual in zip(uut._mutators_of_default_value, generator):
    #         n += 1
    #         self.assertEqual(truncate(expected(self.default_value)), actual(self.default_value))
    #     for expected, actual in zip(map(truncate, uut._magic_debug_values), generator):
    #         n += 1
    #         self.assertEqual(expected, actual)
    #     for i in range(0, len(self.default_default_value)):
    #         for expected_fuzz_string in uut._fuzz_strings_1byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 1 :]
    #             self.assertEqual(truncate(expected_value), actual_value)
    #     for i in range(0, len(self.default_default_value) - 1):
    #         for expected_fuzz_string in uut._fuzz_strings_2byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 2 :]
    #             self.assertEqual(truncate(expected_value), actual_value)
    #     for i in range(0, len(self.default_default_value) - 3):
    #         for expected_fuzz_string in uut._fuzz_strings_4byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 4 :]
    #             self.assertEqual(truncate(expected_value), actual_value)
    #
    #     self.assertEqual(n, uut.num_mutations(default_value=self.default_value))
    #
    # def test_mutations_size(self):
    #     size = 5
    #     pad = b"\x41"
    #
    #     def fit_to_size(b):
    #         fullpad = b"\x41" * 5
    #         pad_len = max(0, size - len(b))
    #         return b[0:size] + fullpad[0:pad_len]
    #
    #     uut = self._given_bytes_size(size=size, padding=pad)
    #     generator = uut.mutations(default_value=self.default_default_value)
    #
    #     n = 0
    #     for expected, actual in zip(map(fit_to_size, uut._fuzz_library), generator):
    #         n += 1
    #         self.assertEqual(expected, actual)
    #     for expected, actual in zip(uut._mutators_of_default_value, generator):
    #         n += 1
    #         self.assertEqual(fit_to_size(expected(self.default_value)), actual(self.default_value))
    #     for expected, actual in zip(map(fit_to_size, uut._magic_debug_values), generator):
    #         n += 1
    #         self.assertEqual(expected, actual)
    #     for i in range(0, len(self.default_default_value)):
    #         for expected_fuzz_string in uut._fuzz_strings_1byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 1 :]
    #             self.assertEqual(fit_to_size(expected_value), actual_value)
    #     for i in range(0, len(self.default_default_value) - 1):
    #         for expected_fuzz_string in uut._fuzz_strings_2byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 2 :]
    #             self.assertEqual(fit_to_size(expected_value), actual_value)
    #     for i in range(0, len(self.default_default_value) - 3):
    #         for expected_fuzz_string in uut._fuzz_strings_4byte:
    #             n += 1
    #             actual_callable = next(generator)
    #             actual_value = actual_callable(self.default_value)
    #             expected_value = self.default_value[0:i] + expected_fuzz_string + self.default_value[i + 4 :]
    #             self.assertEqual(fit_to_size(expected_value), actual_value)
    #
    #     self.assertEqual(n, uut.num_mutations(default_value=self.default_value))


if __name__ == "__main__":
    unittest.main()
