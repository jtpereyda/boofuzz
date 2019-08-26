from .base_primitive import BasePrimitive


class Numbers(BasePrimitive):
    def __init__(self, value, max_len=-1, padding="", signed=False, fuzzable=True, name=None):
        """
        Primitive that cycles through a library of "bad" numbers, represented as strings.

        @type  value:         str
        @param value:         Default number value
        @type  max_len:       int
        @param max_len:       (Optional, def=-1) Max length of strings returned, leave -1 for any length
        @type  padding:       str
        @param padding:       (Optional, def="") String for left-padding, for use with max_len. Default is " "
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Numbers, self).__init__()

        self.max_len = max_len
        self.padding = padding
        self.signed = signed
        self._fuzzable = fuzzable
        self._name = name

        nums = [
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

        if not self._fuzz_library:
            val_list = nums + signed_nums if signed else nums
            if max_len > -1:
                for v in val_list:
                    if len(v) > max_len:
                        continue
                    total_pad = max_len - len(v)
                    if padding:
                        len_pad = len(padding)
                        n_pad = total_pad // len_pad
                        r_pad = total_pad % len_pad
                        self._fuzz_library.append(padding * n_pad + padding[:r_pad] + v)
                    else:
                        self._fuzz_library.append(" " * total_pad + v)
            else:
                self._fuzz_library = val_list

    @property
    def name(self):
        return self._name
