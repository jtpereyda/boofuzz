import struct

import six

from .bit_field import BitField


class Byte(BitField):
    def __init__(self, *args, **kwargs):
        # Inject the one parameter we care to pass in (width)
        width = 8
        max_num = None

        super(Byte, self).__init__(width, max_num, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "B", value)[0]
        return super(Byte, self).encode(value, mutation_context)

