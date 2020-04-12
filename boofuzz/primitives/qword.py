import struct

import six

from boofuzz.primitives.bit_field import BitField


class QWord(BitField):
    def __init__(self, *args, **kwargs):
        width = 64
        max_num = None

        super(QWord, self).__init__(width, max_num, *args, **kwargs)

    def mutations(self):
        for v in super(QWord, self).mutations():
            yield v

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "Q", value)[0]
        return super(QWord, self).encode(value, mutation_context)
