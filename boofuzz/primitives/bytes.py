import functools
import operator

from funcy import compose

from ..fuzzable import Fuzzable


class Bytes(Fuzzable):
    """Primitive that fuzzes a binary byte string with arbitrary length.

    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type default_value: bytes, optional
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value,
        defaults to b""
    :type size: int, optional
    :param size: Static size of this field, leave None for dynamic, defaults to None
    :type padding: chr, optional
    :param padding: Value to use as padding to fill static field size, defaults to b"\\x00"
    :type max_len: int, optional
    :param max_len: Maximum string length, defaults to None
    :type fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    # This binary strings will always included as testcases.
    _fuzz_library = [
        b"",
        b"\x00",
        b"\xFF",
        b"A" * 10,
        b"A" * 100,
        b"A" * 1000,
        b"A" * 5000,
        b"A" * 10000,
        b"A" * 100000,
    ]

    # from https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_debug_values
    _magic_debug_values = [
        b"\x00\x00\x81#",
        b"\x00\xfa\xca\xde",
        b"\x1b\xad\xb0\x02",
        b"\x8b\xad\xf0\r",
        b"\xa5\xa5\xa5\xa5",
        b"\xa5",
        b"\xab\xab\xab\xab",
        b"\xab\xad\xba\xbe",
        b"\xab\xba\xba\xbe",
        b"\xab\xad\xca\xfe",
        b"\xb1k\x00\xb5",
        b"\xba\xad\xf0\r",
        b"\xba\xaa\xaa\xad",
        b'\xba\xd2""',
        b"\xba\xdb\xad\xba\xdb\xad",
        b"\xba\xdc\x0f\xfe\xe0\xdd\xf0\r",
        b"\xba\xdd\xca\xfe",
        b"\xbb\xad\xbe\xef",
        b"\xbe\xef\xca\xce",
        b"\xc0\x00\x10\xff",
        b"\xca\xfe\xba\xbe",
        b"\xca\xfe\xd0\r",
        b"\xca\xfe\xfe\xed",
        b"\xcc\xcc\xcc\xcc",
        b"\xcd\xcd\xcd\xcd",
        b"\r\x15\xea^",
        b"\xdd\xdd\xdd\xdd",
        b"\xde\xad\x10\xcc",
        b"\xde\xad\xba\xbe",
        b"\xde\xad\xbe\xef",
        b"\xde\xad\xca\xfe",
        b"\xde\xad\xc0\xde",
        b"\xde\xad\xfa\x11",
        b"\xde\xad\xf0\r",
        b"\xde\xfe\xc8\xed",
        b"\xde\xad\xde\xad",
        b"\xeb\xeb\xeb\xeb",
        b"\xfa\xde\xde\xad",
        b"\xfd\xfd\xfd\xfd",
        b"\xfe\xe1\xde\xad",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xee\xfe\xee",
    ]

    # This is a list of "interesting" 1,2 and 4 byte binary strings.
    # The lists are used to replace each block of 1, 2 or 4 byte in the original
    # value with each of those "interesting" values.
    _fuzz_strings_1byte = [b"\x00", b"\x01", b"\x7F", b"\x80", b"\xFF"] + [
        i for i in _magic_debug_values if len(i) == 1
    ]

    _fuzz_strings_2byte = [
        b"\x00\x00",
        b"\x01\x00",
        b"\x00\x01",
        b"\x7F\xFF",
        b"\xFF\x7F",
        b"\xFE\xFF",
        b"\xFF\xFE",
        b"\xFF\xFF",
    ] + [i for i in _magic_debug_values if len(i) == 2]

    _fuzz_strings_4byte = [
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x01",
        b"\x01\x00\x00\x00",
        b"\x7F\xFF\xFF\xFF",
        b"\xFF\xFF\xFF\x7F",
        b"\xFE\xFF\xFF\xFF",
        b"\xFF\xFF\xFF\xFE",
        b"\xFF\xFF\xFF\xFF",
    ] + [i for i in _magic_debug_values if len(i) == 4]

    _mutators_of_default_value = [
        functools.partial(operator.mul, 2),
        functools.partial(operator.mul, 10),
        functools.partial(operator.mul, 100),
    ]

    def __init__(self, name=None, default_value=b"", size=None, padding=b"\x00", max_len=None, *args, **kwargs):
        super(Bytes, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.padding = padding

    def mutations(self, default_value):
        for fuzz_value in self._iterate_fuzz_cases(default_value):
            if callable(fuzz_value):
                yield compose(self._adjust_mutation_for_size, fuzz_value)
            else:
                yield self._adjust_mutation_for_size(fuzz_value=fuzz_value)

    def _adjust_mutation_for_size(self, fuzz_value):
        if self.size is not None:
            if len(fuzz_value) > self.size:
                return fuzz_value[: self.max_len]
            else:
                return fuzz_value + self.padding * (self.size - len(fuzz_value))
        elif self.max_len is not None and len(fuzz_value) > self.max_len:
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value

    def _iterate_fuzz_cases(self, default_value):
        for fuzz_value in self._fuzz_library:
            yield fuzz_value
        for fuzz_value in self._mutators_of_default_value:
            yield fuzz_value
        for fuzz_value in self._magic_debug_values:
            yield fuzz_value
        for i in range(0, len(default_value)):
            for fuzz_bytes in self._fuzz_strings_1byte:

                def f(value):
                    if i < len(value):
                        return value[:i] + fuzz_bytes + value[i + 1 :]
                    else:
                        return value

                yield f
        for i in range(0, len(default_value) - 1):
            for fuzz_bytes in self._fuzz_strings_2byte:

                def f(value):
                    if i < len(value) - 1:
                        return value[:i] + fuzz_bytes + value[i + 2 :]
                    else:
                        return value

                yield f

        for i in range(0, len(default_value) - 3):
            for fuzz_bytes in self._fuzz_strings_4byte:

                def f(value):
                    if i < len(value) - 3:
                        return value[:i] + fuzz_bytes + value[i + 4 :]
                    else:
                        return value

                yield f

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        :param default_value:
        """
        return sum(
            (
                len(self._fuzz_library),
                len(self._mutators_of_default_value),
                len(self._magic_debug_values),
                len(self._fuzz_strings_1byte) * max(0, len(default_value) - 0),
                len(self._fuzz_strings_2byte) * max(0, len(default_value) - 1),
                len(self._fuzz_strings_4byte) * max(0, len(default_value) - 3),
            )
        )

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return value
