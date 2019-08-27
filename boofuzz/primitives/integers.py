from boofuzz.primitives.bit_field import BitField


class Integers(BitField):
    def __init__(self, value, bits=128, max_num=None, signed=True, name=None, *args, **kwargs):
        """
        The Integers primitive represents integers of arbitrary value.

        @type  value:          int
        @param value:          Default integer value
        @type  bits:           int
        @param bits:           Width of integer numbers, in bits. Default: 128. Ignored if max_num is set
        @type  max_num:        int
        @param max_num:        Maximum number to iterate up to. Takes precedence over bits
        @type  full_range:     bool
        @param full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values
        @type  fuzzable:       bool
        @param fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:           str
        @param name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        self.output_format = "ascii"
        self.signed = signed
        self.bits = bits
        self.max_num = max_num

        super(Integers, self).__init__(value, width=bits, signed=signed, name=None, output_format="ascii")
