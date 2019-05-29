import struct

import six

from boofuzz.primitives.bit_field import BitField


class Word(BitField):
    def __init__(self, value, *args, **kwargs):
        # Inject our width argument
        width = 16
        max_num = None

        super(Word, self).__init__(value, width, max_num, *args, **kwargs)

        if not isinstance(self._value, (six.integer_types, list, tuple)):
            self._value = struct.unpack(self.endian + "H", self._value)[0]
