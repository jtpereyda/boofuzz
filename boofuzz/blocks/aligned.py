from ..fuzzable_block import FuzzableBlock


class Aligned(FuzzableBlock):
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(self, request, modulus, pattern="\x00"):
        """
        Create a sizer block bound to the block with the specified name. Size blocks that size their own parent or
        grandparent are allowed.

        :type  request:       Request
        :param request:       Request this block belongs to
        :type  modulus:     int
        :param modulus:     Pad length of child content to this many bytes
        :type  pattern:     bytes
        :param pattern:     Pad using these byte(s)
        """
        super().__init__(request=request)
        self._modulus = modulus
        self._pattern = pattern

    def encode(self, value, child_data, mutation_context):
        padding_length = self._modulus - (len(child_data) % self._modulus)
        a, b = divmod(padding_length, len(self._pattern))
        return child_data + self._pattern * a + self._pattern[:b]
