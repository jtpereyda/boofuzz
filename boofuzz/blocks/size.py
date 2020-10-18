from functools import wraps

from .. import helpers, primitives
from ..fuzzable import Fuzzable


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


class Size(Fuzzable):
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(
        self,
        name,
        block_name,
        request=None,
        offset=0,
        length=4,
        endian="<",
        output_format="binary",
        inclusive=False,
        signed=False,
        math=None,
        *args,
        **kwargs
    ):
        """
        Create a sizer block bound to the block with the specified name. Size blocks that size their own parent or
        grandparent are allowed.

        :type  block_name:    str
        :param block_name:    Name of block to apply sizer to
        :type  request:       Request
        :param request:       Request this block belongs to
        :type  length:        int
        :param length:        (Optional, def=4) Length of sizer
        :type  offset:        int
        :param offset:        (Optional, def=0) Offset for calculated size value
        :type  endian:        chr
        :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        :type  output_format: str
        :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
        :type  inclusive:     bool
        :param inclusive:     (Optional, def=False) Should the sizer count its own length?
        :type  signed:        bool
        :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        :type  math:          def
        :param math:          (Optional, def=None) Apply the mathematical op defined in this function to the size
        """

        super(Size, self).__init__(name=name, default_value=None, *args, **kwargs)
        self.block_name = block_name
        self.request = request
        self.offset = offset
        self.length = length
        self.endian = endian
        self.format = output_format
        self.inclusive = inclusive
        self.signed = signed
        self.math = math

        self.bit_field = primitives.BitField(
            name="innerBitField",
            default_value=0,
            width=self.length * 8,
            endian=self.endian,
            output_format=self.format,
            signed=self.signed,
        )
        self._rendered = b""
        self._fuzz_complete = False

        if not self.math:
            self.math = lambda x: x

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def mutations(self, default_value):
        for mutation in self.bit_field.mutations(None):
            yield mutation

    def num_mutations(self, default_value):
        """
        Wrap the num_mutations routine of the internal bit_field primitive.

        :param default_value:
        :rtype:  int
        :return: Number of mutated forms this primitive can take.
        """

        return self.bit_field.get_num_mutations()

    def encode(self, value, mutation_context):
        if value is None:  # default
            if self._recursion_flag:
                return self._get_dummy_value()
            else:
                return helpers.str_to_bytes(
                    self._length_to_bytes(self._calculated_length(mutation_context=mutation_context))
                )
        else:
            return self.bit_field.encode(value=value, mutation_context=mutation_context)

    def _get_dummy_value(self):
        return self.length * b"\x00"

    def _calculated_length(self, mutation_context):
        return (
            self.offset
            + self._inclusive_length_of_self
            + self._length_of_target_block(mutation_context=mutation_context)
        )

    def _length_to_bytes(self, length):
        return primitives.BitField._render_int(
            value=self.math(length),
            output_format=self.format,
            bit_width=self.length * 8,
            endian=self.endian,
            signed=self.signed,
        )

    @property
    def _inclusive_length_of_self(self):
        """Return length of self or zero if inclusive flag is False."""
        if self.inclusive:
            return self.length
        else:
            return 0

    @_may_recurse
    def _length_of_target_block(self, mutation_context):
        """Return length of target block, including mutations if mutation applies."""
        target_block = self.request.resolve_name(self.context_path, self.block_name)
        return len(target_block.render(mutation_context=mutation_context))

    @property
    @_may_recurse
    def _original_length_of_target_block(self):
        """Return length of target block, including mutations if it is currently mutated."""
        target_block = self.request.resolve_name(self.context_path, self.block_name)
        length = len(target_block.original_value)
        return length

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self.length
