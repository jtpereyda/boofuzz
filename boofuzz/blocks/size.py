from functools import wraps

from .. import helpers, primitives
from ..fuzzable import Fuzzable
from ..fuzzable_wrapper import FuzzableWrapper
from ..mutation import Mutation


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

    def __init__(self, block_name, request, offset=0, length=4, endian="<", output_format="binary", inclusive=False,
                 signed=False, math=None):
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

        super().__init__()
        self.block_name = block_name
        self.request = request
        self.offset = offset
        self.length = length
        self.endian = endian
        self.format = output_format
        self.inclusive = inclusive
        self.signed = signed
        self.math = math

        self.bit_field = FuzzableWrapper(
            fuzz_object=primitives.BitField(
                self.length * 8, endian=self.endian, output_format=self.format, signed=self.signed
            ),
            fuzzable=True,
            default_value=0,
        )
        self._rendered = b""
        self._fuzz_complete = False

        if not self.math:
            self.math = lambda x: x

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def mutations(self):
        for mutation in self.bit_field.fuzz_object.mutations():
            yield mutation

    def num_mutations(self, default_value):
        """
        Wrap the num_mutations routine of the internal bit_field primitive.

        :param default_value:
        :rtype:  int
        :return: Number of mutated forms this primitive can take.
        """

        return self.bit_field.num_mutations()

    def encode(self, value, child_data, mutation_context):
        if value is None:  # default
            if self._recursion_flag:
                return self._get_dummy_value()
            else:
                return helpers.str_to_bytes(self._length_to_bytes(self._calculated_length(
                    mutation_context=mutation_context)))
        else:
            return self.bit_field.fuzz_object.encode(value=value, child_data=None, mutation_context=mutation_context)

    def _get_dummy_value(self):
        return self.length * "\x00"

    def _render(self, value=None):
        if value is None:
            length = self._calculated_length(Mutation())
            return helpers.str_to_bytes(self._length_to_bytes(length))
        else:
            return self.bit_field.fuzz_object.encode(value=value, child_data=None)

    def _calculated_length(self, mutation_context):
        return self.offset + self._inclusive_length_of_self + self._length_of_target_block(
            mutation_context=mutation_context)

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
        return len(target_block.render_mutated(mutation_context=mutation_context))

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
        return len(self._render())  # TODO fix length method, if needed

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
