import struct

import six

from .bit_field import BitField


class Byte(BitField):
    def __init__(self, *args, **kwargs):
        # Inject the one parameter we care to pass in (width)
        width = 8
        max_num = None

        super(Byte, self).__init__(width, max_num, *args, **kwargs)

    def mutations(self, default_value):
        if not isinstance(default_value, (six.integer_types, list, tuple)):
            default_value = struct.unpack(self.endian + "B", default_value)[0]
        for v in super(Byte, self).mutations(default_value=default_value):
            yield v
