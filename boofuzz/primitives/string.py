from __future__ import division

import itertools
import math
import random

import six
from future.standard_library import install_aliases
from six.moves import range

from ..fuzzable import Fuzzable

install_aliases()


class String(Fuzzable):
    """Primitive that cycles through a library of "bad" strings.

    The class variable 'fuzz_library' contains a list of
    smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
    the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
    each instantiated primitive.

    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type default_value: str
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value.
    :type size: int, optional
    :param size: Static size of this field, leave None for dynamic, defaults to None
    :type padding: chr, optional
    :param padding: Value to use as padding to fill static field size, defaults to "\\x00"
    :type encoding: str, optional
    :param encoding: String encoding, ex: utf_16_le for Microsoft Unicode, defaults to ascii
    :type max_len: int, optional
    :param max_len: Maximum string length, defaults to None
    :type fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    # Has to be sorted to avoid duplicates
    _fuzz_library = [
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
        "",  # strings ripped from spike (and some others I added)
        "$(reboot)",
        "$;reboot",
        "%00",
        "%00/",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "%0a reboot %0a",
        "%0Areboot",
        "%0Areboot%0A",
        "%0DCMD=$'reboot';$CMD",
        '%0DCMD=$"reboot";$CMD',
        "%0Dreboot",
        "%0Dreboot%0D",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,
        "%n" * 100,  # format strings.
        "%n" * 500,
        "%s" * 100,
        "%s" * 500,
        "%u0000",
        "& reboot &",
        "& reboot",
        "&&CMD=$'reboot';$CMD",
        '&&CMD=$"reboot";$CMD',
        "&&reboot",
        "&&reboot&&",
        "&CMD=$'reboot';$CMD",
        '&CMD=$"reboot";$CMD',
        "&reboot",
        "&reboot&",
        "'reboot'",
        "..:..:..:..:..:..:..:..:..:..:..:..:..:",
        "/%00/",
        "/." * 5000,
        "/.../" + "B" * 5000 + "\x00\x00",
        "/.../.../.../.../.../.../.../.../.../.../",
        "/../../../../../../../../../../../../boot.ini",
        "/../../../../../../../../../../../../etc/passwd",
        "/.:/" + "A" * 5000 + "\x00\x00",
        "/\\" * 5000,
        "/index.html|reboot|",
        "; reboot",
        ";CMD=$'reboot';$CMD",
        ';CMD=$"reboot";$CMD',
        ";id",
        ";notepad;",
        ";reboot",
        ";reboot/n",
        ";reboot;",
        ";reboot|",
        ";system('reboot')",
        ";touch /tmp/SULLEY;",
        ";|reboot|",
        '<!--#exec cmd="reboot"-->',
        "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
        "<reboot",
        "<reboot%0A",
        "<reboot%0D",
        "<reboot;",
        '"%n"' * 500,
        '"%s"' * 500,
        "\\\\*",
        "\\\\?\\",
        "\nnotepad\n",
        "\nreboot\n",
        "\r\n" * 100,  # miscellaneous.
        "\x01\x02\x03\x04",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,
        "\xde\xad\xbe\xef",  # some binary strings.
        "^CMD=$'reboot';$CMD",
        '^CMD=$"reboot";$CMD',
        "^reboot",
        "`reboot`",
        "a);reboot",
        "a);reboot;",
        "a);reboot|",
        "a)|reboot",
        "a)|reboot;",  # fuzzdb command injection
        "a;reboot",
        "a;reboot;",
        "a;reboot|",
        "a|reboot",
        "CMD=$'reboot';$CMD",
        'CMD=$"reboot";$CMD',
        "FAIL||CMD=$'reboot';$CMD",
        'FAIL||CMD=$"reboot";$CMD',
        "FAIL||reboot",
        "id",
        "id;",
        "id|",
        "reboot",
        "reboot;",
        "reboot|",
        "| reboot",
        "|CMD=$'reboot';$CMD",
        '|CMD=$"reboot";$CMD',
        "|nid",
        "|notepad",
        "|reboot",
        "|reboot;",
        "|reboot|",
        "|touch /tmp/SULLEY",  # command injection.
        "||reboot;",
        "||reboot|",
    ]

    long_string_seeds = [
        "C",
        "1",
        "<",
        ">",
        "'",
        '"',
        "/",
        "\\",
        "?",
        "=",
        "a=",
        "&",
        ".",
        ",",
        "(",
        ")",
        "]",
        "[",
        "%",
        "*",
        "-",
        "+",
        "{",
        "}",
        "\x14",
        "\x00",
        "\xFE",  # expands to 4 characters under utf1
        "\xFF",  # expands to 4 characters under utf1
    ]

    _long_string_lengths = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]
    _long_string_deltas = [-2, -1, 0, 1, 2]
    _extra_long_string_lengths = [99999, 100000, 500000, 1000000]

    _variable_mutation_multipliers = [2, 10, 100]

    def __init__(
        self, name=None, default_value="", size=None, padding=b"\x00", encoding="utf-8", max_len=None, *args, **kwargs
    ):
        super(String, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.size = size
        self.max_len = max_len
        if self.size is not None:
            self.max_len = self.size
        self.encoding = encoding
        self.padding = padding
        if isinstance(padding, six.text_type):
            self.padding = self.padding.encode(self.encoding)
        self._static_num_mutations = None
        self.random_indices = {}

        random.seed(0)  # We want constant random numbers to generate reproducible test cases
        previous_length = 0
        # For every length add a random number of random indices to the random_indices dict. Prevent duplicates by
        # adding only indices in between previous_length and current length.
        for length in self._long_string_lengths:
            self.random_indices[length] = random.sample(
                range(previous_length, length), random.randint(1, self._long_string_lengths[0])
            )
            previous_length = length

    def _yield_long_strings(self, sequences):
        """
        Given a sequence, yield a number of selectively chosen strings lengths of the given sequence.

        @type  sequences: list(str)
        @param sequences: Sequence to repeat for creation of fuzz strings.
        """
        for sequence in sequences:
            for size in [
                length + delta
                for length, delta in itertools.product(self._long_string_lengths, self._long_string_deltas)
            ]:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            for size in self._extra_long_string_lengths:
                if self.max_len is None or size <= self.max_len:
                    data = sequence * math.ceil(size / len(sequence))
                    yield data[:size]
                else:
                    break

            if self.max_len is not None:
                data = sequence * math.ceil(self.max_len / len(sequence))
                yield data

        for size in self._long_string_lengths:
            if self.max_len is None or size <= self.max_len:
                s = "D" * size
                for loc in self.random_indices[size]:
                    yield s[:loc] + "\x00" + s[loc + 1 :]  # Replace character at loc with terminator
            else:
                break

    def _yield_variable_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            value = default_value * length
            if value not in self._fuzz_library:
                yield value
                if self.max_len is not None and len(value) >= self.max_len:
                    break

    def _adjust_mutation_for_size(self, fuzz_value):
        if self.max_len is not None and self.max_len < len(fuzz_value):
            return fuzz_value[: self.max_len]
        else:
            return fuzz_value

    def mutations(self, default_value):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        Args:
            default_value (str): Default value of element.

        Yields:
            str: Mutations
        """
        last_val = None

        for val in itertools.chain(
            self._fuzz_library,
            self._yield_variable_mutations(default_value),
            self._yield_long_strings(self.long_string_seeds),
        ):
            current_val = self._adjust_mutation_for_size(val)
            if last_val == current_val:
                continue
            last_val = current_val
            yield current_val

        # TODO: Add easy and sane string injection from external file/s

    def encode(self, value, mutation_context=None):
        value = six.ensure_binary(value, self.encoding, "replace")
        # pad undersized library items.
        if self.size is not None and len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """
        variable_num_mutations = sum(1 for _ in self._yield_variable_mutations(default_value=default_value))
        if self._static_num_mutations is None:
            #  Counting the number of mutations with default value "" results in 0 variable_num_mutations 3 * "" = ""
            self._static_num_mutations = sum(1 for _ in self.mutations(default_value=""))
        return self._static_num_mutations + variable_num_mutations
