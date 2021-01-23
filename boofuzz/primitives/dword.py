import struct

import six

from boofuzz.primitives.bit_field import BitField


class DWord(BitField):
    """The 4 byte sized bit field primitive. Inherits parameters from :class:`boofuzz.BitField`"""

    def __init__(self, default_value, *args, **kwargs):
        # Inject our width argument
        super(DWord, self).__init__(default_value=default_value, width=32, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "L", value)[0]
        return super(DWord, self).encode(value, mutation_context)
