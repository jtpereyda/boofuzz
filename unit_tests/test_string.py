from __future__ import division

import itertools
import math
import unittest
from collections import Counter, OrderedDict

import pytest
import six
from future.standard_library import install_aliases
from six.moves import map, zip

from boofuzz import *

install_aliases()


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestString(unittest.TestCase):
    def _given_string(self):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return String(name="boofuzz-unit-test-name", default_value=self.default_value)

    def _given_string_max_len(self, max_len):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return String(name="boofuzz-unit-test-name", default_value=self.default_value, max_len=max_len)

    def _given_string_size(self, size, padding, encoding):
        self.default_value = "ABCDEFGH"
        self.default_default_value = "\x00" * len(self.default_value)
        return String(
            name="boofuzz-unit-test-name",
            default_value=self.default_value,
            size=size,
            padding=padding,
            encoding=encoding,
        )

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
            for size in [
                length + delta
                for length, delta in itertools.product(String._long_string_lengths, String._long_string_deltas)
            ]:
                n += 1
                expected = sequence * math.ceil(size / len(sequence))
                self.assertEqual(expected[:size], next(generator))

            for size in String._extra_long_string_lengths:
                n += 1
                expected = sequence * math.ceil(size / len(sequence))
                self.assertEqual(expected[:size], next(generator))

        for size in String._long_string_lengths:
            s = "D" * size
            for loc in uut.random_indices[size]:
                n += 1
                expected = s[:loc] + "\x00" + s[loc + 1 :]
                self.assertEqual(expected, next(generator))

        self.assertRaises(StopIteration, lambda: next(generator))
        self.assertEqual(n, uut.num_mutations(default_value=self.default_value))
        list_of_duplicates = [
            item for item, count in Counter(uut.mutations(default_value=self.default_value)).items() if count > 1
        ]
        self.assertEqual(0, len(list_of_duplicates))

    def test_mutations_max_len(self):
        lengths = [5, 10, 128, 1000, 100000]

        for max_len in lengths:
            uut = self._given_string_max_len(max_len=max_len)
            generator = uut.mutations(default_value=self.default_default_value)

            def truncate(b):
                return b[:max_len]

            n = 0
            for expected, actual in zip(OrderedDict.fromkeys(list(map(truncate, String._fuzz_library))), generator):
                n += 1
                self.assertEqual(expected, actual)

            for expected, actual in zip(String._variable_mutation_multipliers, generator):
                n += 1
                self.assertEqual(truncate(self.default_default_value * expected), actual)
                if max_len <= len(self.default_default_value * expected):
                    break

            for sequence in String.long_string_seeds:
                for size in [
                    length + delta
                    for length, delta in itertools.product(String._long_string_lengths, String._long_string_deltas)
                ]:
                    if size <= max_len:
                        n += 1
                        expected = sequence * math.ceil(size / len(sequence))
                        self.assertEqual(truncate(expected[:size]), next(generator))

                for size in String._extra_long_string_lengths:
                    if size <= max_len:
                        n += 1
                        expected = sequence * math.ceil(size / len(sequence))
                        self.assertEqual(truncate(expected[:size]), next(generator))

                if max_len not in String._extra_long_string_lengths + [
                    length + delta
                    for length, delta in itertools.product(String._long_string_lengths, String._long_string_deltas)
                ]:
                    n += 1
                    expected = sequence * math.ceil(max_len / len(sequence))
                    self.assertEqual(truncate(expected), next(generator))

            for size in String._long_string_lengths:
                if size <= max_len:
                    s = "D" * size
                    for loc in uut.random_indices[size]:
                        expected = s[:loc] + "\x00" + s[loc + 1 :]
                        n += 1
                        self.assertEqual(truncate(expected), next(generator))

            self.assertRaises(StopIteration, lambda: next(generator))
            self.assertEqual(n, uut.num_mutations(default_value=self.default_value))
            list_of_duplicates = [
                item for item, count in Counter(uut.mutations(default_value=self.default_value)).items() if count > 1
            ]
            self.assertEqual(0, len(list_of_duplicates))

    def test_mutations_size(self):
        lengths = [5, 10, 128, 1000, 100000]
        pad = b"\x41"
        encoding = "utf-8"

        def fit_to_size(b):
            b = six.ensure_binary(b[:max_len], encoding=encoding)
            pad_len = max(0, max_len - len(b))
            return b + pad * pad_len

        for max_len in lengths:
            uut = self._given_string_size(size=max_len, padding=pad, encoding=encoding)
            generator = uut.mutations(default_value=self.default_default_value)

            n = 0
            for expected, actual in zip(OrderedDict.fromkeys(list(map(fit_to_size, String._fuzz_library))), generator):
                n += 1
                self.assertEqual(expected, uut.encode(actual))

            for expected, actual in zip(String._variable_mutation_multipliers, generator):
                n += 1
                self.assertEqual(fit_to_size(self.default_default_value * expected), uut.encode(actual))
                if max_len <= len(self.default_default_value * expected):
                    break

            for sequence in String.long_string_seeds:
                for size in [
                    length + delta
                    for length, delta in itertools.product(String._long_string_lengths, String._long_string_deltas)
                ]:
                    if size <= max_len:
                        n += 1
                        expected = sequence * math.ceil(size / len(sequence))
                        self.assertEqual(fit_to_size(expected[:size]), uut.encode(next(generator)))

                for size in String._extra_long_string_lengths:
                    if size <= max_len:
                        n += 1
                        expected = sequence * math.ceil(size / len(sequence))
                        self.assertEqual(fit_to_size(expected[:size]), uut.encode(next(generator)))

                if max_len not in String._extra_long_string_lengths + [
                    length + delta
                    for length, delta in itertools.product(String._long_string_lengths, String._long_string_deltas)
                ]:
                    n += 1
                    expected = sequence * math.ceil(max_len / len(sequence))
                    self.assertEqual(fit_to_size(expected), uut.encode(next(generator)))

            for length in String._long_string_lengths:
                if length <= max_len:
                    s = "D" * length
                    for loc in uut.random_indices[length]:
                        expected = s[:loc] + "\x00" + s[loc + 1 :]
                        n += 1
                        self.assertEqual(fit_to_size(expected), uut.encode(next(generator)))

            self.assertRaises(StopIteration, lambda: next(generator))
            self.assertEqual(n, uut.num_mutations(default_value=self.default_value))
            list_of_duplicates = [
                item for item, count in Counter(uut.mutations(default_value=self.default_value)).items() if count > 1
            ]
            self.assertEqual(0, len(list_of_duplicates))


if __name__ == "__main__":
    unittest.main()
