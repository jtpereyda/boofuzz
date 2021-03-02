import random
import struct

from past.builtins import xrange

from boofuzz import helpers
from ..fuzzable import Fuzzable
from ..mutation import Mutation


class RandomData(Fuzzable):
    """Generate a random chunk of data while maintaining a copy of the original.

    A random length range can be specified. For a static length, set min/max length to be the same.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value,
        defaults to None
    :type default_value: str or bytes, optional
    :param min_length: Minimum length of random block, defaults to 0
    :type min_length: int, optional
    :param max_length: Maximum length of random block, defaults to 1
    :type max_length: int, optional
    :param max_mutations: Number of mutations to make before reverting to default, defaults to 25
    :type max_mutations: int, optional
    :param step: If not None, step count between min and max reps, otherwise random, defaults to None
    :type step: int, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    :type fuzzable: bool, optional
    """

    def __init__(
        self, name=None, default_value="", min_length=0, max_length=1, max_mutations=25, step=None, *args, **kwargs
    ):
        default_value = helpers.str_to_bytes(default_value)

        super(RandomData, self).__init__(name=name, default_value=default_value, *args, **kwargs)

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
