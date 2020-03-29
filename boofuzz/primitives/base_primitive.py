import abc

from .. import helpers
from ..ifuzzable import IFuzzable
from ..mutation import Mutation


class BasePrimitive(IFuzzable):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    @property
    def fuzzable(self):
        return self._fuzzable

    @property
    def original_value(self):
        return self._original_value

    def __init__(self):
        self._fuzzable = True  # flag controlling whether or not the given primitive is to be fuzzed.
        self._mutant_index = 0  # current mutation index into the fuzz library.
        self._original_value = None  # original value of primitive.
        self._original_value_rendered = None  # original value as rendered

        self._fuzz_complete = False  # this flag is raised when the mutations are exhausted.
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self._rendered = b""  # rendered value of primitive.
        self._value = None  # current value of primitive.

    def mutations(self):
        for val in self._fuzz_library:
            yield Mutation(mutations={self.qualified_name: val})

    def encode(self, value, **kwargs):
        return self._render(value)

    def num_mutations(self):
        return len(self._fuzz_library)

    def _render(self, value):
        """
        Render an arbitrary value.

        Args:
            value: Value to render.

        Returns:
            bytes: Rendered value
        """
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, repr(self._value))

    def __len__(self):
        return len(self._value)

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
