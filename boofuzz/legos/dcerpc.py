# MSRPC NDR TYPES

import struct
from .. import blocks, primitives, sex
from ..helpers import calculate_four_byte_padding


class NdrConformantArray(blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrConformantArray).__init__(name, request)

        self.value = value
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
        if self._rendered == "":
            self._rendered = "\x00\x00\x00\x00"
        else:
            string_with_padding = self._rendered + calculate_four_byte_padding(self._rendered)
            self._rendered = struct.pack("<L", len(self._rendered)) + string_with_padding

        return self._rendered


class NdrString(blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrString, self).__init__(name, request)

        self.value = value
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
        if self._rendered == "":
            self._rendered = "\x00\x00\x00\x00"
        else:
            # ensure null termination.
            self._rendered += "\x00"

            # format accordingly.
            length = len(self._rendered)
            self._rendered = "" \
                             + struct.pack("<L", length) \
                             + struct.pack("<L", 0) \
                             + struct.pack("<L", length) \
                             + self._rendered \
                             + calculate_four_byte_padding(self._rendered)

        return self._rendered


class NdrWString(blocks.Block):
    """
    Note: this is not for fuzzing the RPC protocol but rather just representing an NDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(NdrWString).__init__(name, request)

        self.value = value
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
        if self._rendered == "":
            self._rendered = "\x00\x00\x00\x00"
        else:
            # unicode encode and null terminate.
            self._rendered = self._rendered.encode("utf-16le") + "\x00"

            # format accordingly.
            length = len(self._rendered)
            self._rendered = "" \
                             + struct.pack("<L", length) \
                             + struct.pack("<L", 0) \
                             + struct.pack("<L", length) \
                             + self._rendered \
                             + calculate_four_byte_padding(self._rendered)

        return self._rendered
