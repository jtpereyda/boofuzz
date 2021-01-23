from ..fuzzable_block import FuzzableBlock


class Aligned(FuzzableBlock):
    """FuzzableBlock that aligns its contents to a certain number of bytes

    :type  modulus:     int
    :param modulus:     Pad length of child content to this many bytes
    :type  request:     boofuzz.Request
    :param request:     Request this block belongs to
    :type  pattern:     bytes
    :param pattern:     Pad using these byte(s)
    :type  name:        str, optional
    :param name:        Name, for referencing later. Names should always be provided, but if not, a default name will
                        be given, defaults to None
    """

    def __init__(self, modulus, request=None, pattern=b"\x00", name=None, *args, **kwargs):
        super(Aligned, self).__init__(name=name, default_value=None, request=request, *args, **kwargs)
        self._modulus = modulus
        self._pattern = pattern

    def encode(self, value, mutation_context):
        child_data = self.get_child_data(mutation_context=mutation_context)
        padding_length = self._modulus - (len(child_data) % self._modulus)
        a, b = divmod(padding_length, len(self._pattern))
        return child_data + self._pattern * a + self._pattern[:b]
