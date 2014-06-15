########################################################################################################################
### MSRPC NDR TYPES
########################################################################################################################

import struct
from sulley import blocks, primitives, sex
from sulley.helpers import calculate_four_byte_padding

class NdrConformantArray(blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrConformantArray).__init__(name, request)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.ndr_conformant_array DEFAULT VALUE")

        self.push(primitives.String(self.value))

    def render(self):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][array][pad]
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            string_with_padding = self.rendered + calculate_four_byte_padding(self.rendered)
            self.rendered = struct.pack("<L", len(self.rendered)) + string_with_padding

        return self.rendered

class NdrString (blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrString).__init__(name, request)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.String(self.value))

    def render(self):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            # ensure null termination.
            self.rendered += "\x00"

            # format accordingly.
            length        = len(self.rendered)
            self.rendered = "" \
                + struct.pack("<L", length)   \
                + struct.pack("<L", 0)      \
                + struct.pack("<L", length) \
                + self.rendered             \
                + calculate_four_byte_padding(self.rendered)

        return self.rendered

class NdrWString(blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrWString).__init__(name, request)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.String(self.value))

    def render(self):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][dword offset][dword passed size][string][pad]
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self.rendered == "":
            self.rendered = "\x00\x00\x00\x00"
        else:
            # unicode encode and null terminate.
            self.rendered = self.rendered.encode("utf-16le") + "\x00"

            # format accordingly.
            length        = len(self.rendered)
            self.rendered = "" \
                    + struct.pack("<L", length) \
                    + struct.pack("<L", 0)      \
                    + struct.pack("<L", length) \
                    + self.rendered             \
                    + calculate_four_byte_padding(self.rendered)

        return self.rendered