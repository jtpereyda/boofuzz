from ..fuzzable_block import FuzzableBlock


class Aligned(FuzzableBlock):
    """FuzzableBlock that aligns its contents to a certain number of bytes

    :type  name:        str, optional
    :param name:        Name, for referencing later. Names should always be provided, but if not, a default name will
                        be given, defaults to None
    :type  modulus:     int, optional
    :param modulus:     Pad length of child content to this many bytes, defaults to 1
    :type  request:     boofuzz.Request, optional
    :param request:     Request this block belongs to
    :type  pattern:     bytes, optional
    :param pattern:     Pad using these byte(s)
    :type  fuzzable:    bool, optional
    :param fuzzable:    Enable/disable fuzzing of this block, defaults to true
    """

    def __init__(self, name=None, modulus=1, request=None, pattern=b"\x00", *args, **kwargs):
        super(Aligned, self).__init__(name=name, default_value=None, request=request, *args, **kwargs)
        self._modulus = modulus
        self._pattern = pattern

    def encode(self, value, mutation_context):
        child_data = self.get_child_data(mutation_context=mutation_context)
        padding_length = self._modulus - (len(child_data) % self._modulus)
        a, b = divmod(padding_length, len(self._pattern))
        return child_data + self._pattern * a + self._pattern[:b]
