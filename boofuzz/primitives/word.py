import struct

import six

from boofuzz.primitives.bit_field import BitField


class Word(BitField):
    def __init__(self, *args, **kwargs):
        # Inject our width argument
        width = 16
        super(Word, self).__init__(width, None, *args, **kwargs)

    def mutations(self):
        for v in super(Word, self).mutations():
            yield v

    def encode(self, value, child_data, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "H", value)[0]
        return super(Word, self).encode(value, child_data, mutation_context)
