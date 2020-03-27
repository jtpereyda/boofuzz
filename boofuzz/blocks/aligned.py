from functools import wraps

from .. import helpers, primitives
from ..ifuzzable import IFuzzable


class Aligned(IFuzzable):
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(
            self,
            request,
            modulus,
            fuzzable=False,
            name=None,
            pattern="\x00",
    ):
        """
        Create a sizer block bound to the block with the specified name. Size blocks that size their own parent or
        grandparent are allowed.

        :type  request:       Request
        :param request:       Request this block belongs to
        :type  fuzzable:      bool
        :param fuzzable:      (Optional, def=False) Enable/disable fuzzing of this sizer
        :type  name:          str
        :param name:          Name of this sizer field
        :type  modulus:     int
        :param modulus:     Pad length of child content to this many bytes
        :type  pattern:     bytes
        :param pattern:     Pad using these byte(s)
        """

        self._fuzzable = fuzzable
        self._name = name

        self.request = request
        self._modulus = modulus
        self._pattern = pattern

        self.stack = []  # block item stack.

    @property
    def original_value(self):
        return self.render()

    def mutations(self):
        for item in self.stack:
            self.request.mutant = item
            for value, rendered in item.mutations():
                mutations_map = {item.name: (value, rendered)}
                yield mutations_map, self._render(mutations_map=mutations_map)

    def num_mutations(self):
        """
        Wrap the num_mutations routine of the internal bit_field primitive.

        :rtype:  int
        :return: Number of mutated forms this primitive can take.
        """
        return 0

    def _align_it(self, data):
        """Align data.

        :param data: bytes to align
        :type data: bytes
        :return: data aligned to this object's modulus using pattern
        :rtype: bytes
        """
        padding_length = self._modulus - (len(data) % self._modulus)
        a, b = divmod(padding_length, len(self._pattern))
        return data + self._pattern * a + self._pattern[:b]

    def render(self):
        """
        Render the sizer.

        :return: Rendered value.
        """
        return self._render({})

    def _render(self, mutations_map):
        """
        Step through every item on this blocks stack and render it. Subsequent blocks recursively render their stacks.
        """
        rendered = b""
        for item in self.stack:
            if item.name in mutations_map:
                rendered += mutations_map[item.name][1]
            else:
                rendered += item.render()

        return self._align_it(rendered)

    def push(self, item):
        """
        Push an arbitrary item onto this blocks stack.
        @type item: BasePrimitive | Block | boofuzz.blocks.size.Size | boofuzz.blocks.repeat.Repeat
        @param item: Some primitive/block/etc.
        """

        self.stack.append(item)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return len(self.render())

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
