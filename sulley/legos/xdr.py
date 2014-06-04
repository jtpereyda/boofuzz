########################################################################################################################
### XDR TYPES (http://www.freesoft.org/CIE/RFC/1832/index.htm)
########################################################################################################################

import struct
from sulley import blocks, primitives, sex


########################################################################################################################
def xdr_pad (string):
    return "\x00" * ((4 - (len(string) & 3)) & 3)


########################################################################################################################
class string (blocks.block):
    '''
    Note: this is not for fuzzing the XDR protocol but rather just representing an XDR string for fuzzing the actual
    client.
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.xdr_string DEFAULT VALUE")

        self.push(primitives.string(self.value))


    def render (self):
        '''
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][array][pad]
        '''

        # let the parent do the initial render.
        blocks.block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            self.rendered = struct.pack(">L", len(self.rendered)) + self.rendered + xdr_pad(self.rendered)

        return self.rendered
