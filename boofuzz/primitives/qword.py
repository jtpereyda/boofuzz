import struct

from boofuzz.primitives.bit_field import BitField


class QWord(BitField):
    def __init__(self, value, *args, **kwargs):
        width = 64
        max_num = None

        super(QWord, self).__init__(value, width, max_num, *args, **kwargs)

        if type(self._value) not in [int, long, list, tuple]:
            self._value = struct.unpack(self.endian + "Q", self._value)[0]
