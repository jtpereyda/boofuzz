from .base_primitive import BasePrimitive
from .. import helpers


class Bytes(BasePrimitive):
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

    def __init__(self, value, size=None, padding=b"\x00", fuzzable=True, max_len=None, name=None):
        """
        Primitive that fuzzes a binary byte string with arbitrary length.

        @type  value:      bytes
        @param value:      Default string value
        @type  size:       int
        @param size:       (Optional, def=None) Static size of this field, leave None for dynamic.
        @type  padding:    chr
        @param padding:    (Optional, def=b"\\x00") Value to use as padding to fill static field size.
        @type  fuzzable:   bool
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:    int
        @param max_len:    (Optional, def=None) Maximum string length
        @type  name:       str
        @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Bytes, self).__init__()

        assert isinstance(value, bytes)
        self._original_value = value
        self._value = self._original_value
        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.padding = padding
        self._fuzzable = fuzzable
        self._name = name
        self.this_library = [self._value * 2, self._value * 10, self._value * 100]

    @property
    def name(self):
        return self._name

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        while True:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False

            if self._mutant_index < len(self._fuzz_library):
                # stage 1a: replace with _fuzz_library items
                alreadyDone = 0
                self._value = self._fuzz_library[self._mutant_index - alreadyDone]
            elif self._mutant_index < len(self._fuzz_library) + len(self.this_library):
                # stage 1b: replace with this_library items
                alreadyDone = len(self._fuzz_library)
                self._value = self.this_library[self._mutant_index - alreadyDone]
            elif self._mutant_index < len(self._fuzz_library) + len(self.this_library) + len(self._magic_debug_values):
                # stage 1c: replace with _magic_debug_value items
                alreadyDone = len(self._fuzz_library) + len(self.this_library)
                self._value = self._magic_debug_values[self._mutant_index - alreadyDone]
            else:
                # stage 2a: replace every single byte with a value from _fuzz_strings_1byte
                # stage 2b: replace every double byte block with a value from _fuzz_strings_2byte
                # stage 2c: replace every four byte block with a value from _fuzz_strings_4byte
                alreadyDone = len(self._fuzz_library) + len(self.this_library) + len(self._magic_debug_values)
                testcase_nr = self._mutant_index - alreadyDone
                testcases_2a = len(self._fuzz_strings_1byte) * max(0, len(self._original_value) - 0)
                testcases_2b = len(self._fuzz_strings_2byte) * max(0, len(self._original_value) - 1)
                testcases_2c = len(self._fuzz_strings_4byte) * max(0, len(self._original_value) - 3)
                if testcase_nr < testcases_2a:
                    j = testcase_nr % len(self._fuzz_strings_1byte)
                    i = testcase_nr // len(self._fuzz_strings_1byte)
                    self._value = self._original_value[:i] + self._fuzz_strings_1byte[j] + self._original_value[i + 1 :]
                elif testcase_nr < testcases_2a + testcases_2b:
                    testcase_nr -= testcases_2a
                    j = testcase_nr % len(self._fuzz_strings_2byte)
                    i = testcase_nr // len(self._fuzz_strings_2byte)
                    self._value = self._original_value[:i] + self._fuzz_strings_2byte[j] + self._original_value[i + 2 :]
                elif testcase_nr < testcases_2a + testcases_2b + testcases_2c:
                    testcase_nr -= testcases_2a
                    testcase_nr -= testcases_2b
                    j = testcase_nr % len(self._fuzz_strings_4byte)
                    i = testcase_nr // len(self._fuzz_strings_4byte)
                    self._value = self._original_value[:i] + self._fuzz_strings_4byte[j] + self._original_value[i + 4 :]
                else:
                    # should not be reachable!
                    assert False

            # increment the mutation count.
            self._mutant_index += 1

            # check if the current testcase aligns
            if self.size is not None and len(self._value) > self.size:
                continue  # too long, skip this one
            if self.max_len is not None and len(self._value) > self.max_len:
                # truncate the current value
                self._value = self._value[: self.max_len]

            # _value has now been mutated and therefore we return True to indicate success
            return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        num = len(self._fuzz_library) + len(self.this_library) + len(self._magic_debug_values)
        num += len(self._fuzz_strings_1byte) * max(0, len(self._original_value) - 0)
        num += len(self._fuzz_strings_2byte) * max(0, len(self._original_value) - 1)
        num += len(self._fuzz_strings_4byte) * max(0, len(self._original_value) - 3)
        return num

    def _render(self, value):
        """
        Render string value, properly padded.
        """

        value = helpers.str_to_bytes(value)

        # if size is set, then pad undersized values.
        if self.size is not None:
            value += self.padding * (self.size - len(value))

        return helpers.str_to_bytes(value)
