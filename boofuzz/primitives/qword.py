import struct

import six

from boofuzz.primitives.bit_field import BitField


class QWord(BitField):
    """The 8 byte sized bit field primitive.

    :type  name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  default_value: int, optional
    :param default_value: Default integer value, defaults to 0
    :type  max_num: int, optional
    :param max_num: Maximum number to iterate up to, defaults to None
    :type  endian: char, optional
    :param endian: Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  output_format: str, optional
    :param output_format: Output format, "binary" or "ascii", defaults to binary
    :type  signed: bool, optional
    :param signed: Make size signed vs. unsigned (applicable only with format="ascii"), defaults to False
    :type  full_range: bool, optional
    :param full_range: If enabled the field mutates through *all* possible values, defaults to False
    :type  fuzz_values: list, optional
    :param fuzz_values: List of custom fuzz values to add to the normal mutations, defaults to None
    :type  fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    def __init__(self, *args, **kwargs):
        # Inject our width argument
        super(QWord, self).__init__(width=64, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "Q", value)[0]
        return super(QWord, self).encode(value, mutation_context)
