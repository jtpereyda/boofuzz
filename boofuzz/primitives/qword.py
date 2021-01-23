import struct

import six

from boofuzz.primitives.bit_field import BitField


class QWord(BitField):
    """The 8 byte sized bit field primitive. Inherits parameters from :class:`boofuzz.BitField`"""

    def __init__(self, default_value, *args, **kwargs):
        # Inject our width argument
        super(QWord, self).__init__(default_value=default_value, width=64, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "Q", value)[0]
        return super(QWord, self).encode(value, mutation_context)
