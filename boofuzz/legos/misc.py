# Misc Types
from __future__ import absolute_import

from .. import blocks, exception, helpers, primitives


class DNSHostname(blocks.Block):
    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(DNSHostname).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.String())

    def render(self):
        """
        We overload and extend the render routine in order to properly insert substring lengths.
        """

        # let the parent do the initial render.
        blocks.Block.render(self)

        new_str = b""

        # replace dots (.) with the substring length.
        for part in self._rendered.split(b"."):
            new_str += bytes(len(part)) + part

        # be sure to null terminate too.
        self._rendered = new_str + b"\x00"

        return helpers.str_to_bytes(self._rendered)


class Tag(blocks.Block):
    def __init__(self, name, request, value, options=None):
        if not options:
            options = {}

        super(Tag, self).__init__(name, request)

        self.value = value
        self.options = options

        if not self.value:
            raise exception.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        # <example>
        # [delim][string][delim]

        self.push(primitives.Delim(name=name + "_DELIM1", default_value="<"))
        self.push(primitives.String(name=name + "_STR", default_value=""))
        self.push(primitives.Delim(name=name + "_DELIM2", default_value=">"))
