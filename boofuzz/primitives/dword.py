import struct

import six

from boofuzz.primitives.bit_field import BitField


class DWord(BitField):
    def __init__(self, value, *args, **kwargs):
        # Inject our width argument
        width = 32
        max_num = None

        super(DWord, self).__init__(value, width, max_num, *args, **kwargs)

        if not isinstance(self._value, (six.integer_types, list, tuple)):
            self._value = struct.unpack(self.endian + "L", self._value)[0]
