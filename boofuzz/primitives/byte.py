import struct

import six

from .bit_field import BitField


class Byte(BitField):
    """The byte sized bit field primitive. Inherits parameters from :class:`boofuzz.BitField`"""

    def __init__(self, default_value, *args, **kwargs):
        # Inject the one parameter we care to pass in (width)
        super(Byte, self).__init__(default_value=default_value, width=8, *args, **kwargs)

    def encode(self, value, mutation_context):
        if not isinstance(value, (six.integer_types, list, tuple)):
            value = struct.unpack(self.endian + "B", value)[0]
        return super(Byte, self).encode(value, mutation_context)
