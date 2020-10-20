from .base_primitive import BasePrimitive
from .. import helpers


class Delim(BasePrimitive):
    def __init__(self, name, default_value, *args, **kwargs):
        """
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

        @type  default_value:    chr
        @param default_value:    Original value
        """

        super(Delim, self).__init__(name, default_value, *args, **kwargs)

        self._default_value = default_value

        if self._default_value:
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
