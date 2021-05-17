import random

from ..fuzzable import Fuzzable


class Float(Fuzzable):
    """Primitive that generates random float values within a specific range and with a fixed format.

    :type name: str, optional
    :param name: Name, for referencing lates. Names should always be provided, but if not a default name
        defaults to None
    :type default_value: str
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value.
    :type size: int, optional
    :type s_format: str, optional
    :param s_format: Format of the float value on encoding, defaults to .1f
    :type f_min: float, optional
    :param f_min: Minimal float value that can be generated while fuzzing, defaults to 0.0
    :type f_max: float, optional
    :param f_max: Maximal float value that can be generated while fuzzing, defaults to 100.0
    :type max_mutations: int, optional
    :param max_mutations: Total number of mutations for this individual primitive, defaults to 1000
    :type seed: int or str or bytes or bytearray
    :param seed: Set random.seed() with the given seed for reproducible results
    """

    def __init__(
        self,
        name=None,
        default_value: float = 0.0,
        s_format: str = ".1f",
        f_min: float = 0.0,
        f_max: float = 100.0,
        max_mutations: int = 1000,
        seed=None,
        *args,
        **kwargs,
    ):
        super(Float, self).__init__(name=name, default_value=str(default_value), *args, **kwargs)

        self.s_format = s_format
        self.f_min = f_min
        self.f_max = f_max
        self.max_mutations = max_mutations
        self.seed = seed

    def mutations(self, default_value: float):
        last_val = None
        if self.seed is not None:
            random.seed(self.seed)

        for i in range(self.max_mutations):
            if i == 0:
                current_val = default_value
            else:
                current_val = random.uniform(self.f_min, self.f_max)

            current_val = f"%{self.s_format}" % float(current_val)

            if last_val == current_val:
                continue
            last_val = current_val
            yield current_val

    def encode(self, value, mutation_context=None):
        return value.encode()

    def num_mutations(self, default_value):
        return self.max_mutations
