import struct

from ..constants import LITTLE_ENDIAN
from .base_primitive import BasePrimitive


class BitField(BasePrimitive):
    def __init__(self, value, width, max_num=None, endian=LITTLE_ENDIAN, output_format="binary", signed=False,
                 full_range=False, fuzzable=True, name=None):
        """
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:         int
        @param value:         Default integer value
        @type  width:         int
        @param width:         Width of bit fields
        @type  max_num:       int
        @param max_num:       Maximum number to iterate up to
        @type  endian:        chr
        @param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  output_format: str
        @param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  full_range:    bool
        @param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(BitField, self).__init__()

        assert isinstance(value, (int, long, list, tuple)), "value must be an integer, list, or tuple!"
        assert isinstance(width, (int, long)), "width must be an integer!"

        self._value = self._original_value = value
        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.format = output_format
        self.signed = signed
        self.full_range = full_range
        self._fuzzable = fuzzable
        self._name = name
        self.cyclic_index = 0         # when cycling through non-mutating values

        if not self.max_num:
            self.max_num = self.to_decimal("1" + "0" * width)

        assert isinstance(self.max_num, (int, long)), "max_num must be an integer!"

        if self.full_range:
            # add all possible values.
            for i in xrange(0, self.max_num):
                self._fuzz_library.append(i)
        else:
            if type(value) in [list, tuple]:
                # Use the supplied values as the fuzz library.
                for val in iter(value):
                    self._fuzz_library.append(val)
            else:
                # try only "smart" values.
                self.add_integer_boundaries(0)
                self.add_integer_boundaries(self.max_num / 2)
                self.add_integer_boundaries(self.max_num / 3)
                self.add_integer_boundaries(self.max_num / 4)
                self.add_integer_boundaries(self.max_num / 8)
                self.add_integer_boundaries(self.max_num / 16)
                self.add_integer_boundaries(self.max_num / 32)
                self.add_integer_boundaries(self.max_num)

            # TODO: Add injectable arbitrary bit fields

    @property
    def name(self):
        return self._name

    def add_integer_boundaries(self, integer):
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: int
        @param integer: int to append to fuzz heuristics
        """
        for i in xrange(-10, 10):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self._fuzz_library:
                    self._fuzz_library.append(case)

    def render(self):
        """
        Render the primitive.
        """

        if self.format == "binary":
            bit_stream = ""
            rendered = ""

            # pad the bit stream to the next byte boundary.
            if self.width % 8 == 0:
                bit_stream += self.to_binary()
            else:
                bit_stream = "0" * (8 - (self.width % 8))
                bit_stream += self.to_binary()

            # convert the bit stream from a string of bits into raw bytes.
            for i in xrange(len(bit_stream) / 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                rendered += struct.pack("B", self.to_decimal(chunk))

            # if necessary, convert the endianess of the raw bytes.
            if self.endian == LITTLE_ENDIAN:
                rendered = list(rendered)
                rendered.reverse()
                rendered = "".join(rendered)

            self._rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if self.signed and self.to_binary()[0] == "1":
                max_num = self.to_decimal("1" + "0" * (self.width - 1))
                # chop off the sign bit.
                val = self._value & self.to_decimal("1" * (self.width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                self._rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                self._rendered = "%d" % self._value

        return self._rendered

    def to_binary(self, number=None, bit_count=None):
        """
        Convert a number to a binary string.

        @type  number:    int
        @param number:    (Optional, def=self._value) Number to convert
        @type  bit_count: int
        @param bit_count: (Optional, def=self.width) Width of bit string

        @rtype:  str
        @return: Bit string
        """
        if not number:
            if type(self._value) in [list, tuple]:
                # We have been given a list to cycle through that is not being mutated...
                if self.cyclic_index == len(self._value):
                    # Reset the index.
                    self.cyclic_index = 0
                number = self._value[self.cyclic_index]
                self.cyclic_index += 1
            else:
                number = self._value

        if not bit_count:
            bit_count = self.width

        return "".join(map(lambda x: str((number >> x) & 1), range(bit_count - 1, -1, -1)))

    # noinspection PyMethodMayBeStatic
    def to_decimal(self, binary):
        """
        Convert a binary string to a decimal number.

        @type  binary: str
        @param binary: Binary string

        @rtype:  int
        @return: Converted bit string
        """

        return int(binary, 2)

    def __len__(self):
        return self.width / 8

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
