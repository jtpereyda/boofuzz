########################################################################################################################
### ASN.1 / BER TYPES (http://luca.ntop.org/Teaching/Appunti/asn1.html)
########################################################################################################################

import struct
from sulley import blocks, primitives, sex


########################################################################################################################
class string (blocks.block):
    '''
    [0x04][0x84][dword length][string]

    Where:

        0x04 = string
        0x84 = length is 4 bytes
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options
        self.prefix  = options.get("prefix", "\x04")

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ber_string DEFAULT VALUE")

        str_block = blocks.block(name + "_STR", request)
        str_block.push(primitives.string(self.value))

        self.push(blocks.size(name + "_STR", request, endian=">", fuzzable=True))
        self.push(str_block)


    def render (self):
        # let the parent do the initial render.
        blocks.block.render(self)

        self.rendered = self.prefix + "\x84" + self.rendered

        return self.rendered


########################################################################################################################
class integer (blocks.block):
    '''
    [0x02][0x04][dword]

    Where:

        0x02 = integer
        0x04 = integer length is 4 bytes
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ber_integer DEFAULT VALUE")

        self.push(primitives.dword(self.value, endian=">"))


    def render (self):
        # let the parent do the initial render.
        blocks.block.render(self)

        self.rendered = "\x02\x04" + self.rendered
        return self.rendered