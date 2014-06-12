import struct
from sulley import blocks, primitives, sex


########################################################################################################################
class dns_hostname (blocks.Block):
    def __init__(self, name, request, value, options={}):
        blocks.Block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        self.push(primitives.String(self.value))


    def render(self):
        '''
        We overload and extend the render routine in order to properly insert substring lengths.
        '''

        # let the parent do the initial render.
        blocks.Block.render(self)

        new_str = ""

        # replace dots (.) with the substring length.
        for part in self.rendered.split("."):
            new_str += str(len(part)) + part

        # be sure to null terminate too.
        self.rendered = new_str + "\x00"

        return self.rendered


########################################################################################################################
class tag (blocks.Block):
    def __init__(self, name, request, value, options={}):
        blocks.Block.__init__(self, name, request, None, None, None, None)

        self.value   = value
        self.options = options

        if not self.value:
            raise sex.SullyRuntimeError("MISSING LEGO.tag DEFAULT VALUE")

        # <example>
        # [delim][string][delim]

        self.push(primitives.Delim("<"))
        self.push(primitives.String(self.value))
        self.push(primitives.Delim(">"))