from .base_primitive import BasePrimitive


class Delim(BasePrimitive):
    def __init__(self, value=None, fuzzable=True, name=None):
        """
        Represent a delimiter such as :,\r,\n, ,=,>,< etc... Mutations include repetition, substitution and exclusion.

        @type  value:    chr
        @param value:    Original value
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Delim, self).__init__()

        self._fuzzable = fuzzable
        self._name = name
        self._value = self._original_value = value

        if self._value:
            self._fuzz_library.append(self._value * 2)
            self._fuzz_library.append(self._value * 5)
            self._fuzz_library.append(self._value * 10)
            self._fuzz_library.append(self._value * 25)
            self._fuzz_library.append(self._value * 100)
            self._fuzz_library.append(self._value * 500)
            self._fuzz_library.append(self._value * 1000)

        self._fuzz_library.append("")
        if self._value == " ":
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
        self._fuzz_library.append("\"")
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

    @property
    def name(self):
        return self._name
