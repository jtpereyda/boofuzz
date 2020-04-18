import abc

from .. import helpers
from ..mutator import FuzzNode
from ..mutation import Mutation


class BasePrimitive(FuzzNode):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    def __init__(self, *args, **kwargs):
        super(BasePrimitive, self).__init__(*args, **kwargs)
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.

    def mutations(self, default_value):
        for val in self._fuzz_library:
            yield val

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return value

    def num_mutations(self, default_value):
        return len(self._fuzz_library)
