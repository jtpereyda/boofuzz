import struct

import six

from boofuzz.primitives.bit_field import BitField


class Word(BitField):
    """The 2 byte sized bit field primitive. Inherits parameters from :class:`boofuzz.BitField`"""

    def __init__(self, default_value, *args, **kwargs):
        # Inject our width argument
        super(Word, self).__init__(default_value=default_value, width=16, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "H", value)[0]
        return super(Word, self).encode(value, mutation_context)
