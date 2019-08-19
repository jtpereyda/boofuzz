import six

from .base_primitive import BasePrimitive
from .. import helpers


class Numbers(BasePrimitive):
    def __init__(self,
        value,
        size=-1,
        max_num=None,
        signed=False,
        fuzzable=True,
        name=None,
    ):
        """
        Primitive that cycles through a library of "bad" numbers, represented as strings.

        @type  value:         str
        @param value:         Default number value
        @type  size:          int
        @param size:          (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  max_num:       int
        @param max_num:       Maximum number to iterate up to
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Numbers, self).__init__()

        self._value = self._original_value = value
        self.size = size
        self.max_num = max_num
        self.signed = signed
        self._fuzzable = fuzzable
        self._name = name

        if not self._fuzz_library:
            self._fuzz_library = [
                # taken from https://github.com/minimaxir/big-list-of-naughty-strings
                "0",
                "1",
                "1.00",
                "$1.00",
                "1/2",
                "1E2",
                "1E02",
                "1E+02",
                "1/0",
                "0/0",
                "0.00",
                "0..0",
                ".",
                "0.0.0",
                "0,00",
                "0,,0",
                ",",
                "0,0,0",
                "0.0/0",
                "1.0/0.0",
                "0.0/0.0",
                "1,0/0,0",
                "0,0/0,0",
                "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                "NaN",
                "Infinity",
                "INF",
                "1#INF",
                "1#QNAN",
                "1#SNAN",
                "1#IND",
                "0x0",
                "0xffffffff",
                "0xffffffffffffffff",
                "0xabad1dea",
                "123456789012345678901234567890123456789",
                "1,000.00",
                "1 000.00",
                "1'000.00",
                "1,000,000.00",
                "1 000 000.00",
                "1'000'000.00",
                "1.000,00",
                "1 000,00",
                "1'000,00",
                "1.000.000,00",
                "1 000 000,00",
                "1'000'000,00",
                "01000",
                "08",
                "09",
                "2.2250738585072011e-308",
            ]
            signed_nums = [
                "-1",
                "-1.00",
                "-$1.00",
                "-1/2",
                "-1E2",
                "-1E02",
                "-1E+02",
                "-2147483648/-1",
                "-9223372036854775808/-1",
                "-0",
                "-0.0",
                "+0",
                "+0.0",
                "--1",
                "-",
                "-.",
                "-,",
                "-Infinity",
                "-1#IND",
            ]

            if signed:
                for num in signed_nums:
                    self._fuzz_library.append(num)

            bits = 64
            while bits != 0:
                self._fuzz_library.append(str(1 << bits))
                self._fuzz_library.append(str((1 << bits) + 1))
                self._fuzz_library.append(str((1 << bits) - 1))
                if signed:
                    self._fuzz_library.append(str(-(1 << bits)))
                    self._fuzz_library.append(str(-(1 << bits) + 1))
                    self._fuzz_library.append(str(-(1 << bits) - 1))
                bits = bits // 2

    @property
    def name(self):
        return self._name

    def _render(self, value):
        """
        Render string value, properly padded.
        """

        if isinstance(value, six.text_type):
            value = helpers.str_to_bytes(value)

        # pad undersized library items.
        if len(value) < self.size:
            value += self.padding * (self.size - len(value))
        return helpers.str_to_bytes(value)
