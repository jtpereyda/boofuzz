import random

import six
from future.moves import itertools
from past.builtins import range

from .. import helpers
from ..fuzzable import Fuzzable


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
    :param size: Static size of this field, leave -1 for dynamic, defaults to -1
    :type padding: chr, optional
    :param padding: Value to use as padding to fill static field size, defaults to "\\x00"
    :type encoding: str, optional
    :param encoding: String encoding, ex: utf_16_le for Microsoft Unicode, defaults to ascii
    :type max_len: int, optional
    :param max_len: Maximum string length, defaults to -1
    :type fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    _fuzz_library = [
        "",
        # strings ripped from spike (and some others I added)
        "/.:/" + "A" * 5000 + "\x00\x00",
        "/.../" + "B" * 5000 + "\x00\x00",
        "/.../.../.../.../.../.../.../.../.../.../",
        "/../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../boot.ini",
        "..:..:..:..:..:..:..:..:..:..:..:..:..:",
        "\\\\*",
        "\\\\?\\",
        "/\\" * 5000,
        "/." * 5000,
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "\x01\x02\x03\x04",
        "/%00/",
        "%00/",
        "%00",
        "%u0000",
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff" * 20,
        # format strings.
        "%n" * 100,
        "%n" * 500,
        '"%n"' * 500,
        "%s" * 100,
        "%s" * 500,
        '"%s"' * 500,
        # command injection.
        "|touch /tmp/SULLEY",
        ";touch /tmp/SULLEY;",
        "|notepad",
        ";notepad;",
        "\nnotepad\n",
        "|reboot",
        ";reboot;",
        "\nreboot\n",
        # fuzzdb command injection
        "a)|reboot;",
        "CMD=$'reboot';$CMD",
        "a;reboot",
        "a)|reboot",
        "|reboot;",
        "'reboot'",
        '^CMD=$"reboot";$CMD',
        "`reboot`",
        "%0DCMD=$'reboot';$CMD",
        "/index.html|reboot|",
        "%0a reboot %0a",
        "|reboot|",
        "||reboot;",
        ";reboot/n",
        "id",
        ";id",
        "a;reboot|",
        "&reboot&",
        "%0Areboot",
        "a);reboot",
        "$;reboot",
        '&CMD=$"reboot";$CMD',
        '&&CMD=$"reboot";$CMD',
        ";reboot",
        "id;",
        ";reboot;",
        "&CMD=$'reboot';$CMD",
        "& reboot &",
        "; reboot",
        "&&CMD=$'reboot';$CMD",
        "reboot",
        "^CMD=$'reboot';$CMD",
        ";CMD=$'reboot';$CMD",
        "|reboot",
        "<reboot;",
        "FAIL||reboot",
        "a);reboot|",
        '%0DCMD=$"reboot";$CMD',
        "reboot|",
        "%0Areboot%0A",
        "a;reboot;",
        'CMD=$"reboot";$CMD',
        "&&reboot",
        "||reboot|",
        "&&reboot&&",
        "^reboot",
        ";|reboot|",
        "|CMD=$'reboot';$CMD",
        "|nid",
        "&reboot",
        "a|reboot",
        "<reboot%0A",
        'FAIL||CMD=$"reboot";$CMD',
        "$(reboot)",
        "<reboot%0D",
        ";reboot|",
        "id|",
        "%0Dreboot",
        "%0Areboot%0A",
        "%0Dreboot%0D",
        ";system('reboot')",
        '|CMD=$"reboot";$CMD',
        ';CMD=$"reboot";$CMD',
        "<reboot",
        "a);reboot;",
        "& reboot",
        "| reboot",
        "FAIL||CMD=$'reboot';$CMD",
        '<!--#exec cmd="reboot"-->',
        "reboot;",
        # some binary strings.
        "\xde\xad\xbe\xef",
        "\xde\xad\xbe\xef" * 10,
        "\xde\xad\xbe\xef" * 100,
        "\xde\xad\xbe\xef" * 1000,
        "\xde\xad\xbe\xef" * 10000,
        # miscellaneous.
        "\r\n" * 100,
        "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
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

    _long_string_lengths = [128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]
    _long_string_deltas = [-2, -1, 0, 1, 2]
    _extra_long_string_lengths = [5000, 10000, 20000, 99999, 100000, 500000, 1000000]

    _variable_mutation_multipliers = [2, 10, 100]

    def __init__(
        self, name=None, default_value="", size=-1, padding=b"\x00", encoding="ascii", max_len=-1, *args, **kwargs
    ):
        super(String, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.size = size
        self.max_len = max_len
        if self.size > -1:
            self.max_len = self.size
        self.padding = padding
        self.encoding = encoding

        self.random_indices = {}

        random.seed(0)
        for length in self._long_string_lengths:
            self.random_indices[length] = []
            for _ in range(random.randint(1, 10)):  # Number of null bytes to insert (random)
                loc = random.randint(1, length)  # Location of random byte
                self.random_indices[length].append(loc)

    def _yield_long_strings(self, sequences):
        """
        Given a sequence, yield a number of selectively chosen strings lengths of the given sequence.

        @type  sequences: list(str)
        @param sequences: Sequence to repeat for creation of fuzz strings.
        """
        for sequence in sequences:
            for size in self._long_string_lengths:
                for delta in self._long_string_deltas:
                    yield sequence * (size + delta)

        for size in self._long_string_lengths:
            s = "D" * size
            for loc in self.random_indices[size]:
                s = s[:loc] + "\x00" + s[loc:]
                yield s

        for sequence in sequences:
            for size in self._extra_long_string_lengths:
                yield sequence * size

    def _yield_variable_mutations(self, default_value):
        for length in self._variable_mutation_multipliers:
            yield default_value * length
        # doesn't make sense while we're yielding strings:
        # for length in self._variable_mutation_multipliers:
        #     yield default_value * length + b"\xfe"

    def mutations(self, default_value):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        Args:
            default_value (str): Default value of element.

        Yields:
            str: Mutations
        """

        for val in itertools.chain(
            self._fuzz_library,
            self._yield_variable_mutations(default_value),
            self._yield_long_strings(self.long_string_seeds),
        ):
            if self.max_len < 0 or len(val) <= self.max_len:
                yield val

        # TODO: Add easy and sane string injection from external file/s

    def encode(self, value, mutation_context):
        if isinstance(value, six.text_type):
            value = helpers.str_to_bytes(value)
        # pad undersized library items.
        if len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return helpers.str_to_bytes(value)

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return sum(
            (
                len(self._fuzz_library),
                len(self._variable_mutation_multipliers),
                (len(self.long_string_seeds) * len(self._long_string_lengths) * len(self._long_string_deltas)),
                sum((len(indices) for _, indices in self.random_indices.items())),
                (len(self._extra_long_string_lengths) * len(self.long_string_seeds)),
            )
        )
