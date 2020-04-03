import struct

import six

from boofuzz.primitives.bit_field import BitField


class QWord(BitField):
    def __init__(self, *args, **kwargs):
        width = 64
        max_num = None

        super(QWord, self).__init__(width, max_num, *args, **kwargs)

    def mutations(self, default_value):
        if not isinstance(default_value, (six.integer_types, list, tuple)):
            default_value = struct.unpack(self.endian + "Q", default_value)[0]
        for v in super(QWord, self).mutations(default_value=default_value):
            yield v
