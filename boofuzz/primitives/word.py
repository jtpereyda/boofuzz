import struct

import six

from boofuzz.primitives.bit_field import BitField


class Word(BitField):
    def __init__(self, *args, **kwargs):
        # Inject our width argument
        width = 16
        super(Word, self).__init__(width, None, *args, **kwargs)

    def mutations(self, default_value):
        if not isinstance(default_value, (six.integer_types, list, tuple)):
            default_value = struct.unpack(self.endian + "H", default_value)[0]
        for v in super(Word, self).mutations(default_value=default_value):
            yield v
