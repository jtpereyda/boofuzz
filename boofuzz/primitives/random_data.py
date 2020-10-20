import random
import struct

from past.builtins import xrange

from boofuzz import helpers
from ..fuzzable import Fuzzable
from ..mutation import Mutation


class RandomData(Fuzzable):
    def __init__(self, name, value, min_length, max_length, max_mutations=25, step=None, *args, **kwargs):
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
        @type  step:          int
        @param step:          (Optional, def=None) If not null, step count between min and max reps, otherwise random
        """

        super(RandomData, self).__init__(name, value, *args, **kwargs)

        self._value = self._original_value = helpers.str_to_bytes(value)
        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self.step = step
        if self.step:
            self.max_mutations = (self.max_length - self.min_length) // self.step + 1

    def mutations(self, default_value):
        """
        Mutate the primitive value returning False on completion.

        Args:
            default_value (str): Default value of element.

        Yields:
            str: Mutations
        """
        for i in range(0, self.get_num_mutations()):
            # select a random length for this string.
            if not self.step:
                length = random.randint(self.min_length, self.max_length)
            # select a length function of the mutant index and the step.
            else:
                length = self.min_length + i * self.step

            value = b""
            for _ in xrange(length):
                value += struct.pack("B", random.randint(0, 255))
            yield Mutation(mutations={self.qualified_name: value})

    def encode(self, value, mutation_context):
        return value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """

        return self.max_mutations
