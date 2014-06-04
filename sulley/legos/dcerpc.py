########################################################################################################################
### MSRPC NDR TYPES
########################################################################################################################

import struct
from sulley import blocks, primitives, sex


########################################################################################################################
def ndr_pad (string):
    return "\x00" * ((4 - (len(string) & 3)) & 3)


########################################################################################################################
class ndr_conformant_array (blocks.block):
    '''
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ndr_conformant_array DEFAULT VALUE")

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
            self.rendered = struct.pack("<L", len(self.rendered)) + self.rendered + ndr_pad(self.rendered)

        return self.rendered


########################################################################################################################
class ndr_string (blocks.block):
    '''
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.string(self.value))


    def render (self):
        '''
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        '''

        # let the parent do the initial render.
        blocks.block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            # ensure null termination.
            self.rendered += "\x00"

            # format accordingly.
            length        = len(self.rendered)
            self.rendered = struct.pack("<L", length) \
                          + struct.pack("<L", 0)      \
                          + struct.pack("<L", length) \
                          + self.rendered             \
                          + ndr_pad(self.rendered)

        return self.rendered


########################################################################################################################
class ndr_wstring (blocks.block):
    '''
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    '''

    def __init__ (self, name, request, value, options={}):
        blocks.block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.string(self.value))


    def render (self):
        '''
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        '''

        # let the parent do the initial render.
        blocks.block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            # unicode encode and null terminate.
            self.rendered = self.rendered.encode("utf-16le") + "\x00"

            # format accordingly.
            length        = len(self.rendered)
            self.rendered = struct.pack("<L", length) \
                          + struct.pack("<L", 0)      \
                          + struct.pack("<L", length) \
                          + self.rendered             \
                          + ndr_pad(self.rendered)

        return self.rendered