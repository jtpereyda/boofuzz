import struct

import six

from boofuzz.primitives.bit_field import BitField


class DWord(BitField):
    def __init__(self, *args, **kwargs):
        # Inject our width argument
        width = 32
        max_num = None

        super(DWord, self).__init__(width, max_num, *args, **kwargs)

    def mutations(self):
        for v in super(DWord, self).mutations():
            yield v

    def encode(self, value, child_data, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "L", value)[0]
        return super(DWord, self).encode(value, child_data, mutation_context)
