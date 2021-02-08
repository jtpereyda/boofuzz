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
    """Create a sizer block bound to the block with the specified name.

    Size blocks that size their own parent or grandparent are allowed.

    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  block_name:    str, optional
    :param block_name:    Name of block to apply sizer to.
    :type  request:       boofuzz.Request, optional
    :param request:       Request this block belongs to.
    :type  offset:        int, optional
    :param offset:        Offset for calculated size value, defaults to 0
    :type  length:        int, optional
    :param length:        Length of sizer, defaults to 4
    :type  endian:        chr, optional
    :param endian:        Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  output_format: str, optional
    :param output_format: Output format, "binary" or "ascii", defaults to binary
    :type  inclusive:     bool, optional
    :param inclusive:     Should the sizer count its own length? Defaults to False
    :type  signed:        bool, optional
    :param signed:        Make size signed vs. unsigned (applicable only with format="ascii"), defaults to False
    :type  math:          def, optional
    :param math:          Apply the mathematical op defined in this function to the size, defaults to None
    :type  fuzzable:      bool, optional
    :param fuzzable:      Enable/disable fuzzing of this block, defaults to true
    """

    def __init__(
        self,
        name=None,
        block_name=None,
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
        if self.request is not None and self.block_name is not None:
            target_block = self.request.resolve_name(self.context_path, self.block_name)
            return len(target_block.render(mutation_context=mutation_context))
        else:
            return 0

    @property
    @_may_recurse
    def _original_length_of_target_block(self):
        """Return length of target block, including mutations if it is currently mutated."""
        if self.request is not None and self.block_name is not None:
            target_block = self.request.resolve_name(self.context_path, self.block_name)
            length = len(target_block.original_value)
            return length
        else:
            return 0

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self.length
