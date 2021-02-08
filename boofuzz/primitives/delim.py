from .base_primitive import BasePrimitive
from .. import helpers


class Delim(BasePrimitive):
    r"""Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value.
    :type default_value: char, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    :type fuzzable: bool, optional
    """

    def __init__(self, name=None, default_value=" ", *args, **kwargs):
        super(Delim, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self._fuzz_library.append(self._default_value * 2)
        self._fuzz_library.append(self._default_value * 5)
        self._fuzz_library.append(self._default_value * 10)
        self._fuzz_library.append(self._default_value * 25)
        self._fuzz_library.append(self._default_value * 100)
        self._fuzz_library.append(self._default_value * 500)
        self._fuzz_library.append(self._default_value * 1000)

        self._fuzz_library.append("")
        if self._default_value == " ":
            self._fuzz_library.append("\t")
            self._fuzz_library.append("\t" * 2)
            self._fuzz_library.append("\t" * 100)

        self._fuzz_library.append(" ")
        self._fuzz_library.append("\t")
        self._fuzz_library.append("\t " * 100)
        self._fuzz_library.append("\t\r\n" * 100)
        self._fuzz_library.append("!")
        self._fuzz_library.append("@")
        self._fuzz_library.append("#")
        self._fuzz_library.append("$")
        self._fuzz_library.append("%")
        self._fuzz_library.append("^")
        self._fuzz_library.append("&")
        self._fuzz_library.append("*")
        self._fuzz_library.append("(")
        self._fuzz_library.append(")")
        self._fuzz_library.append("-")
        self._fuzz_library.append("_")
        self._fuzz_library.append("+")
        self._fuzz_library.append("=")
        self._fuzz_library.append(":")
        self._fuzz_library.append(": " * 100)
        self._fuzz_library.append(":7" * 100)
        self._fuzz_library.append(";")
        self._fuzz_library.append("'")
        self._fuzz_library.append('"')
        self._fuzz_library.append("/")
        self._fuzz_library.append("\\")
        self._fuzz_library.append("?")
        self._fuzz_library.append("<")
        self._fuzz_library.append(">")
        self._fuzz_library.append(".")
        self._fuzz_library.append(",")
        self._fuzz_library.append("\r")
        self._fuzz_library.append("\n")
        self._fuzz_library.append("\r\n" * 64)
        self._fuzz_library.append("\r\n" * 128)
        self._fuzz_library.append("\r\n" * 512)

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)
