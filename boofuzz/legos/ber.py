# ASN.1 / BER TYPES (http://luca.ntop.org/Teaching/Appunti/asn1.html)

from __future__ import absolute_import
from .. import blocks, primitives, sex
from ..constants import BIG_ENDIAN


class String(blocks.Block):
    """
    [0x04][0x84][dword length][string]

    Where:

        0x04 = string
        0x84 = length is 4 bytes
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(String, self).__init__(name, request)

        self.value = value
        self.options = options
        self.prefix = options.get("prefix", "\x04")

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ber_string DEFAULT VALUE")

        str_block = blocks.Block(name + "_STR", request)
        str_block.push(primitives.String(self.value))

        self.push(blocks.Size(name + "_STR", request, endian=BIG_ENDIAN, fuzzable=True))
        self.push(str_block)

    def render(self):
        # let the parent do the initial render.
        blocks.Block.render(self)

        # TODO: What is this I don't even
        self._rendered = self.prefix + "\x84" + self._rendered

        return self._rendered


class Integer(blocks.Block):
    """
    [0x02][0x04][dword]

    Where:

        0x02 = integer
        0x04 = integer length is 4 bytes
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(Integer).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ber_integer DEFAULT VALUE")

        self.push(primitives.DWord(self.value, endian=BIG_ENDIAN))

    def render(self):
        # let the parent do the initial render.
        blocks.Block.render(self)

        self._rendered = "\x02\x04" + self._rendered
        return self._rendered
