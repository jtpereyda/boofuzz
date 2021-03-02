# XDR TYPES (http://www.freesoft.org/CIE/RFC/1832/index.htm)

from __future__ import absolute_import

import struct

from .. import blocks, exception, helpers, primitives
from ..helpers import calculate_four_byte_padding


class String(blocks.Block):
    """
    Note: this is not for fuzzing the XDR protocol but rather just representing an XDR string for fuzzing the actual
    client.
    """

    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(String).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.SullyRuntimeError("MISSING LEGO.xdr_string DEFAULT VALUE")

        self.push(primitives.String())

    def render(self, mutation_context=None):
        """
        We overload and extend the render routine in order to properly pad and prefix the string.

        [dword length][array][pad]
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        # encode the empty string correctly:
        if self._rendered == b"":
            self._rendered = b"\x00\x00\x00\x00"
        else:
            size_header = struct.pack(">L", len(self._rendered))
            self._rendered = size_header + self._rendered + calculate_four_byte_padding(self._rendered)

        return helpers.str_to_bytes(self._rendered)
