import struct

import six

from boofuzz.primitives.bit_field import BitField


class Word(BitField):
    def __init__(self, *args, **kwargs):
        # Inject our width argument
        kwargs["width"] = 16
        super(Word, self).__init__(*args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "H", value)[0]
        return super(Word, self).encode(value, mutation_context)
