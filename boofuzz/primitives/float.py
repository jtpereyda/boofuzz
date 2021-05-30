import random
import struct

from ..fuzzable import Fuzzable


class Float(Fuzzable):
    """Primitive that generates random float values within a specific range and with a fixed format.

    :type name: str, optional
    :param name: Name, for referencing later.
    :type default_value: float
    :param default_value: Value used when the element is not being fuzzed.
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
    :type encode_as_ieee_754: bool, optional
    :param encode_as_ieee_754: Encode the float value as IEEE 754 floating point
    :type endian: str, optional
    :param endian: Change the endianness of IEEE 754 float point representation, defaults to big endian
    """

    def __init__(
        self,
        name=None,
        default_value=0.0,
        s_format=".1f",
        f_min=0.0,
        f_max=100.0,
        max_mutations=1000,
        seed=None,
        encode_as_ieee_754=False,
        endian="big",
        *args,
        **kwargs
    ):

        super(Float, self).__init__(name=name, default_value=str(default_value), *args, **kwargs)

        self.s_format = s_format
        self.f_min = f_min
        self.f_max = f_max
        self.max_mutations = max_mutations
        self.seed = seed
        self.encode_as_ieee_754 = encode_as_ieee_754
        self.endian = endian

    def mutations(self, default_value):
        last_val = None
        if self.seed is not None:
            random.seed(self.seed)

        for i in range(self.max_mutations):
            if i == 0:
                current_val = default_value
            else:
                current_val = random.uniform(self.f_min, self.f_max)

            str_format = "%" + self.s_format
            current_val = str_format % float(current_val)

            if last_val == current_val:
                continue
            last_val = current_val
            yield current_val

    def encode(self, value, mutation_context=None):
        if self.encode_as_ieee_754:
            value = float(value)
            return self.__convert_to_iee_754(value)

        return value.encode()

    def __convert_to_iee_754(self, value):
        if self.endian == "big":
            iee_value = struct.pack(">f", value)
        elif self.endian == "little":
            iee_value = struct.pack("<f", value)
        else:
            error_msg = "Invalid endian argument '%s'. Use 'big' or 'little'." % self.endian
            raise ValueError(error_msg)

        return iee_value

    def num_mutations(self, default_value):
        return self.max_mutations
