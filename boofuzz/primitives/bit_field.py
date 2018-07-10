import struct
from builtins import range

from ..constants import LITTLE_ENDIAN
from .base_primitive import BasePrimitive


def binary_string_to_int(binary):
    """
    Convert a binary string to a decimal number.

    @type  binary: str
    @param binary: Binary string

    @rtype:  int
    @return: Converted bit string
    """

    return int(binary, 2)


def int_to_binary_string(number, bit_width):
    """
    Convert a number to a binary string.

    @type  number:    int
    @param number:    (Optional, def=self._value) Number to convert
    @type  bit_width: int
    @param bit_width: (Optional, def=self.width) Width of bit string

    @rtype:  str
    @return: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


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
            self.max_num = binary_string_to_int("1" + "0" * width)

        assert isinstance(self.max_num, (int, long)), "max_num must be an integer!"

        if self.full_range:
            # add all possible values.
            for i in range(0, self.max_num):
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
        for i in range(-10, 10):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self._fuzz_library:
                    self._fuzz_library.append(case)

    def _render(self, value):
        return self.render_int(value, output_format=self.format, bit_width=self.width, endian=self.endian, signed=self.signed)

    @staticmethod
    def render_int(value, output_format, bit_width, endian, signed):
        """
        Convert value to a bit or byte string.

        Args:
            value (int): Value to convert to a byte string.
            output_format (str): "binary" or "ascii"
            bit_width (int): Width of output in bits.
            endian: BIG_ENDIAN or LITTLE_ENDIAN
            signed (bool):

        Returns:
            str: value converted to a byte string
        """
        if output_format == "binary":
            bit_stream = ""
            rendered = ""

            # pad the bit stream to the next byte boundary.
            if bit_width % 8 == 0:
                bit_stream += int_to_binary_string(value, bit_width)
            else:
                bit_stream = "0" * (8 - (bit_width % 8))
                bit_stream += int_to_binary_string(value, bit_width)

            # convert the bit stream from a string of bits into raw bytes.
            for i in range(len(bit_stream) / 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                rendered += struct.pack("B", binary_string_to_int(chunk))

            # if necessary, convert the endianness of the raw bytes.
            if endian == LITTLE_ENDIAN:
                rendered = list(rendered)
                rendered.reverse()
                rendered = "".join(rendered)

            _rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if signed and int_to_binary_string(value, bit_width)[0] == "1":
                max_num = binary_string_to_int("1" + "0" * (bit_width - 1))
                # chop off the sign bit.
                val = value & binary_string_to_int("1" * (bit_width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                _rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                _rendered = "%d" % value
        return _rendered

    def __len__(self):
        if self.format == "binary":
            return self.width / 8
        else:
            return len(str(self._value))

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
