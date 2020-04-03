import struct

import six

from boofuzz.primitives.bit_field import BitField


class DWord(BitField):
    def __init__(self, *args, **kwargs):
        # Inject our width argument
        width = 32
        max_num = None

        super(DWord, self).__init__(width, max_num, *args, **kwargs)

    def mutations(self, default_value):
        if not isinstance(default_value, (six.integer_types, list, tuple)):
            default_value = struct.unpack(self.endian + "L", default_value)[0]
        for v in super(DWord, self).mutations(default_value=default_value):
            yield v
