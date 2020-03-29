import random

import six
from past.builtins import xrange

from boofuzz import helpers
from .base_primitive import BasePrimitive
from past.builtins import xrange

from ..mutation import Mutation


class RandomData(BasePrimitive):
    def __init__(self, value, min_length, max_length, max_mutations=25, fuzzable=True, step=None, name=None):
        """
        Generate a random chunk of data while maintaining a copy of the original. A random length range
        can be specified.

        For a static length, set min/max length to be the same.

        @type  value:         str
        @param value:         Original value
        @type  min_length:    int
        @param min_length:    Minimum length of random block
        @type  max_length:    int
        @param max_length:    Maximum length of random block
        @type  max_mutations: int
        @param max_mutations: (Optional, def=25) Number of mutations to make before reverting to default
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  step:          int
        @param step:          (Optional, def=None) If not null, step count between min and max reps, otherwise random
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(RandomData, self).__init__()

        self._value = self._original_value = helpers.str_to_bytes(value)
        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self._fuzzable = fuzzable
        self.step = step
        self._name = name
        if self.step:
            self.max_mutations = (self.max_length - self.min_length) // self.step + 1

    def mutations(self):
        """
        Mutate the primitive value returning False on completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """
        if not self._fuzzable:
            return

        for i in range(0, self.num_mutations()):
            # select a random length for this string.
            if not self.step:
                length = random.randint(self.min_length, self.max_length)
            # select a length function of the mutant index and the step.
            else:
                length = self.min_length + i * self.step

            value = ""
            for _ in xrange(length):
                value += chr(random.randint(0, 255))
            yield Mutation(mutations={self.qualified_name: value})

    def encode(self, value, **kwargs):
        return self._render(value)

    def _render(self, value):
        return value

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """

        return self.max_mutations
