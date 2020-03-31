import abc

from .. import helpers
from ..ifuzzable import IFuzzable
from ..mutation import Mutation


class BasePrimitive(IFuzzable):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    def __init__(self):
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.

    def mutations(self):
        for val in self._fuzz_library:
            yield val

    def encode(self, value, child_data, mutation, **kwargs):
        if value is None:
            value = b""
        return value

    def num_mutations(self):
        return len(self._fuzz_library)
