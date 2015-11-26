import random
import struct

from constants import LITTLE_ENDIAN

# TODO: Change primitives to yield instead of returning a bunch of trues (if possible)


class BasePrimitive(object):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    def __init__(self):
        self.fuzz_complete = False  # this flag is raised when the mutations are exhausted.
        self.fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self.fuzzable = True  # flag controlling whether or not the given primitive is to be fuzzed.
        self.mutant_index = 0  # current mutation index into the fuzz library.
        self.original_value = None  # original value of primitive.
        self.rendered = ""  # rendered value of primitive.
        self.value = None  # current value of primitive.

    def exhaust(self):
        """
        Exhaust the possible mutations for this primitive.

        @rtype:  int
        @return: The number of mutations to reach exhaustion
        """

        num = self.num_mutations() - self.mutant_index

        self.fuzz_complete = True
        self.mutant_index = self.num_mutations()
        self.value = self.original_value

        return num

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library, return False on completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # update the current value from the fuzz library.
        self.value = self.fuzz_library[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """

        return len(self.fuzz_library)

    def render(self):
        """
        Nothing fancy on render, simply return the value.
        """

        self.rendered = self.value
        return self.rendered

    def reset(self):
        """
        Reset this primitive to the starting mutation state.
        """

        self.fuzz_complete = False
        self.mutant_index = 0
        self.value = self.original_value

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, repr(self.value))

    def __len__(self):
        return len(self.value)

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True


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

        self.fuzzable = fuzzable
        self.name = name
        self.value = self.original_value = value
        self.s_type = "delim"  # for ease of object identification

        if self.value:
            self.fuzz_library.append(self.value * 2)
            self.fuzz_library.append(self.value * 5)
            self.fuzz_library.append(self.value * 10)
            self.fuzz_library.append(self.value * 25)
            self.fuzz_library.append(self.value * 100)
            self.fuzz_library.append(self.value * 500)
            self.fuzz_library.append(self.value * 1000)

        self.fuzz_library.append("")
        if self.value == " ":
            self.fuzz_library.append("\t")
            self.fuzz_library.append("\t" * 2)
            self.fuzz_library.append("\t" * 100)

        self.fuzz_library.append(" ")
        self.fuzz_library.append("\t")
        self.fuzz_library.append("\t " * 100)
        self.fuzz_library.append("\t\r\n" * 100)
        self.fuzz_library.append("!")
        self.fuzz_library.append("@")
        self.fuzz_library.append("#")
        self.fuzz_library.append("$")
        self.fuzz_library.append("%")
        self.fuzz_library.append("^")
        self.fuzz_library.append("&")
        self.fuzz_library.append("*")
        self.fuzz_library.append("(")
        self.fuzz_library.append(")")
        self.fuzz_library.append("-")
        self.fuzz_library.append("_")
        self.fuzz_library.append("+")
        self.fuzz_library.append("=")
        self.fuzz_library.append(":")
        self.fuzz_library.append(": " * 100)
        self.fuzz_library.append(":7" * 100)
        self.fuzz_library.append(";")
        self.fuzz_library.append("'")
        self.fuzz_library.append("\"")
        self.fuzz_library.append("/")
        self.fuzz_library.append("\\")
        self.fuzz_library.append("?")
        self.fuzz_library.append("<")
        self.fuzz_library.append(">")
        self.fuzz_library.append(".")
        self.fuzz_library.append(",")
        self.fuzz_library.append("\r")
        self.fuzz_library.append("\n")
        self.fuzz_library.append("\r\n" * 64)
        self.fuzz_library.append("\r\n" * 128)
        self.fuzz_library.append("\r\n" * 512)


class Group(BasePrimitive):
    def __init__(self, name, values):
        """
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        @type  name:   str
        @param name:   Name of group
        @type  values: list or str
        @param values: List of possible raw values this group can take.
        """

        super(Group, self).__init__()

        self.name = name
        self.values = values
        self.s_type = "group"

        assert len(self.values) > 0, "You can't have an empty value list for your group!"

        self.value = self.original_value = self.values[0]

        for val in self.values:
            assert isinstance(val, basestring), "Value list may only contain strings or raw data"

    def mutate(self):
        """
        Move to the next item in the values list.

        @rtype:  bool
        @return: False
        """
        # TODO: See if num_mutations() can be done away with (me thinks yes).
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # step through the value list.
        # TODO: break this into a get_value() function, so we can keep mutate as close to standard as possible.
        self.value = self.values[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        """
        Number of values in this primitive.

        @rtype:  int
        @return: Number of values in this primitive.
        """

        return len(self.values)


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

        self.value = self.original_value = str(value)
        self.min_length = min_length
        self.max_length = max_length
        self.max_mutations = max_mutations
        self.fuzzable = fuzzable
        self.step = step
        self.name = name
        self.s_type = "random_data"  # for ease of object identification
        if self.step:
            self.max_mutations = (self.max_length - self.min_length) / self.step + 1

    def mutate(self):
        """
        Mutate the primitive value returning False on completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            return False

        # select a random length for this string.
        if not self.step:
            length = random.randint(self.min_length, self.max_length)
        # select a length function of the mutant index and the step.
        else:
            length = self.min_length + self.mutant_index * self.step

        # reset the value and generate a random string of the determined length.
        self.value = ""
        for i in xrange(length):
            self.value += chr(random.randint(0, 255))

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """

        return self.max_mutations


class Static(BasePrimitive):
    def __init__(self, value, name=None):
        """
        Primitive that contains static content.

        @type  value: str
        @param value: Raw static data
        @type  name:  str
        @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(Static, self).__init__()

        self.fuzz_complete = True
        self.fuzzable = False
        self.value = self.original_value = value
        self.name = name
        self.s_type = "static"

    def mutate(self):
        """
        Always return false, don't fuzz
        """
        return False

    def num_mutations(self):
        """
        We have no mutations
        """
        return 0


class String(BasePrimitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    fuzz_library = []

    def __init__(self, value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, max_len=0, name=None):
        """
        Primitive that cycles through a library of "bad" strings. The class variable 'fuzz_library' contains a list of
        smart fuzz values global across all instances. The 'this_library' variable contains fuzz values specific to
        the instantiated primitive. This allows us to avoid copying the near ~70MB fuzz_library data structure across
        each instantiated primitive.

        @type  value:    str
        @param value:    Default string value
        @type  size:     int
        @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
        @type  padding:  chr
        @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
        @type  encoding: str
        @param encoding: (Optional, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        @type  fuzzable: bool
        @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  max_len:  int
        @param max_len:  (Optional, def=0) Maximum string length
        @type  name:     str
        @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(String, self).__init__()

        self.value = self.original_value = value
        self.size = size
        self.padding = padding
        self.encoding = encoding
        self.fuzzable = fuzzable
        self.name = name
        self.s_type = "string"  # for ease of object identification
        self.this_library = \
            [
                self.value * 2,
                self.value * 10,
                self.value * 100,

                # UTF-8
                # TODO: This can't actually convert these to unicode strings...
                self.value * 2 + "\xfe",
                self.value * 10 + "\xfe",
                self.value * 100 + "\xfe",
            ]
        if not self.fuzz_library:
            self.fuzz_library = \
                [
                    "",
                    # strings ripped from spike (and some others I added)
                    "/.:/" + "A" * 5000 + "\x00\x00",
                    "/.../" + "B" * 5000 + "\x00\x00",
                    "/.../.../.../.../.../.../.../.../.../.../",
                    "/../../../../../../../../../../../../etc/passwd",
                    "/../../../../../../../../../../../../boot.ini",
                    "..:..:..:..:..:..:..:..:..:..:..:..:..:",
                    "\\\\*",
                    "\\\\?\\",
                    "/\\" * 5000,
                    "/." * 5000,
                    "!@#$%%^#$%#$@#$%$$@#$%^^**(()",
                    "%01%02%03%04%0a%0d%0aADSF",
                    "%01%02%03@%04%0a%0d%0aADSF",
                    "\x01\x02\x03\x04",
                    "/%00/",
                    "%00/",
                    "%00",
                    "%u0000",
                    "%\xfe\xf0%\x00\xff",
                    "%\xfe\xf0%\x01\xff" * 20,

                    # format strings.
                    "%n" * 100,
                    "%n" * 500,
                    "\"%n\"" * 500,
                    "%s" * 100,
                    "%s" * 500,
                    "\"%s\"" * 500,

                    # command injection.
                    "|touch /tmp/SULLEY",
                    ";touch /tmp/SULLEY;",
                    "|notepad",
                    ";notepad;",
                    "\nnotepad\n",

                    # some binary strings.
                    "\xde\xad\xbe\xef",
                    "\xde\xad\xbe\xef" * 10,
                    "\xde\xad\xbe\xef" * 100,
                    "\xde\xad\xbe\xef" * 1000,
                    "\xde\xad\xbe\xef" * 10000,

                    # miscellaneous.
                    "\r\n" * 100,
                    "<>" * 500,  # sendmail crackaddr (http://lsd-pl.net/other/sendmail.txt)
                ]

            # add some long strings.
            self.add_long_strings("C")
            self.add_long_strings("1")
            self.add_long_strings("<")
            self.add_long_strings(">")
            self.add_long_strings("'")
            self.add_long_strings("\"")
            self.add_long_strings("/")
            self.add_long_strings("\\")
            self.add_long_strings("?")
            self.add_long_strings("=")
            self.add_long_strings("a=")
            self.add_long_strings("&")
            self.add_long_strings(".")
            self.add_long_strings(",")
            self.add_long_strings("(")
            self.add_long_strings(")")
            self.add_long_strings("]")
            self.add_long_strings("[")
            self.add_long_strings("%")
            self.add_long_strings("*")
            self.add_long_strings("-")
            self.add_long_strings("+")
            self.add_long_strings("{")
            self.add_long_strings("}")
            self.add_long_strings("\x14")
            self.add_long_strings("\x00")
            self.add_long_strings("\xFE")  # expands to 4 characters under utf16
            self.add_long_strings("\xFF")  # expands to 4 characters under utf16

            # add some long strings with null bytes thrown in the middle of them.
            for length in [128, 256, 1024, 2048, 4096, 32767, 0xFFFF]:
                s = "D" * length
                # Number of null bytes to insert (random)
                for i in range(random.randint(1, 10)):
                    # Location of random byte
                    loc = random.randint(1, len(s))
                    s = s[:loc] + "\x00" + s[loc:]
                self.fuzz_library.append(s)

                # TODO: Add easy and sane string injection from external file/s

        # TODO: Make this more clear
        if max_len > 0:
            # If any of our strings are over max_len
            if any(len(s) > max_len for s in self.this_library):
                # Pull out only the ones that aren't
                self.this_library = list(set([s[:max_len] for s in self.this_library]))
            # Same thing here
            if any(len(s) > max_len for s in self.fuzz_library):
                self.fuzz_library = list(set([s[:max_len] for s in self.fuzz_library]))

    def add_long_strings(self, sequence):
        """
        Given a sequence, generate a number of selectively chosen strings lengths of the given sequence and add to the
        string heuristic library.

        @type  sequence: str
        @param sequence: Sequence to repeat for creation of fuzz strings.
        """
        strings = []
        for size in [128, 256, 512, 1024, 2048, 4096, 32768, 0xFFFF]:
            strings.append(sequence * (size - 2))
            strings.append(sequence * (size - 1))
            strings.append(sequence * size)
            strings.append(sequence * (size + 1))
            strings.append(sequence * (size + 2))

        for size in [5000, 10000, 20000, 99999, 100000, 500000, 1000000]:
            strings.append(sequence * size)

        for string in strings:
            self.fuzz_library.append(string)

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library extended with the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self.mutant_index == self.num_mutations():
                self.fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self.fuzzable or self.fuzz_complete:
                self.value = self.original_value
                return False

            # update the current value from the fuzz library.
            self.value = (self.fuzz_library + self.this_library)[self.mutant_index]

            # increment the mutation count.
            self.mutant_index += 1

            # if the size parameter is disabled, break out of the loop right now.
            if self.size == -1:
                break

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self.value) > self.size:
                continue

            # pad undersized library items.
            if len(self.value) < self.size:
                self.value += self.padding * (self.size - len(self.value))
                break

        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        return len(self.fuzz_library) + len(self.this_library)

    def render(self):
        """
        Render the primitive, encode the string according to the specified encoding.
        """
        # try to encode the string properly and fall back to the default value on failure.
        # TODO: Fix this - seems hacky
        try:
            self.rendered = str(self.value).encode(self.encoding)
        except:
            self.rendered = self.value

        return self.rendered


class BitField(BasePrimitive):
    def __init__(self, value, width, max_num=None, endian=LITTLE_ENDIAN, output_format="binary", signed=False,
                 full_range=False, fuzzable=True, name=None):
        """
        The bit field primitive represents a number of variable length and is used to define all other integer types.

        @type  value:         int
        @param value:         Default integer value
        @type  width:         int
        @param width:         Width of bit fields
        @type  max_num:       int
        @param max_num:       Maximum number to iterate up to
        @type  endian:        chr
        @param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  output_format: str
        @param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  full_range:    bool
        @param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        super(BitField, self).__init__()

        assert isinstance(value, (int, long, list, tuple)), "value must be an integer, list, or tuple!"
        assert isinstance(width, (int, long)), "width must be an integer!"

        self.value = self.original_value = value
        self.width = width
        self.max_num = max_num
        self.endian = endian
        self.format = output_format
        self.signed = signed
        self.full_range = full_range
        self.fuzzable = fuzzable
        self.name = name
        self.cyclic_index = 0         # when cycling through non-mutating values

        if not self.max_num:
            self.max_num = self.to_decimal("1" + "0" * width)

        assert isinstance(self.max_num, (int, long)), "max_num must be an integer!"

        if self.full_range:
            # add all possible values.
            for i in xrange(0, self.max_num):
                self.fuzz_library.append(i)
        else:
            if type(value) in [list, tuple]:
                # Use the supplied values as the fuzz library.
                for val in iter(value):
                    self.fuzz_library.append(val)
            else:
                # try only "smart" values.
                self.add_integer_boundaries(0)
                self.add_integer_boundaries(self.max_num / 2)
                self.add_integer_boundaries(self.max_num / 3)
                self.add_integer_boundaries(self.max_num / 4)
                self.add_integer_boundaries(self.max_num / 8)
                self.add_integer_boundaries(self.max_num / 16)
                self.add_integer_boundaries(self.max_num / 32)
                self.add_integer_boundaries(self.max_num)

            # TODO: Add injectable arbitrary bit fields

    def add_integer_boundaries(self, integer):
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library.

        @type  integer: int
        @param integer: int to append to fuzz heuristics
        """
        for i in xrange(-10, 10):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if 0 <= case < self.max_num:
                if case not in self.fuzz_library:
                    self.fuzz_library.append(case)

    def render(self):
        """
        Render the primitive.
        """

        if self.format == "binary":
            bit_stream = ""
            rendered = ""

            # pad the bit stream to the next byte boundary.
            if self.width % 8 == 0:
                bit_stream += self.to_binary()
            else:
                bit_stream = "0" * (8 - (self.width % 8))
                bit_stream += self.to_binary()

            # convert the bit stream from a string of bits into raw bytes.
            for i in xrange(len(bit_stream) / 8):
                chunk_min = 8 * i
                chunk_max = chunk_min + 8
                chunk = bit_stream[chunk_min:chunk_max]
                rendered += struct.pack("B", self.to_decimal(chunk))

            # if necessary, convert the endianess of the raw bytes.
            if self.endian == LITTLE_ENDIAN:
                rendered = list(rendered)
                rendered.reverse()
                rendered = "".join(rendered)

            self.rendered = rendered
        else:
            # Otherwise we have ascii/something else
            # if the sign flag is raised and we are dealing with a signed integer (first bit is 1).
            if self.signed and self.to_binary()[0] == "1":
                max_num = self.to_decimal("1" + "0" * (self.width - 1))
                # chop off the sign bit.
                val = self.value & self.to_decimal("1" * (self.width - 1))

                # account for the fact that the negative scale works backwards.
                val = max_num - val - 1

                # toss in the negative sign.
                self.rendered = "%d" % ~val

            # unsigned integer or positive signed integer.
            else:
                self.rendered = "%d" % self.value

        return self.rendered

    def to_binary(self, number=None, bit_count=None):
        """
        Convert a number to a binary string.

        @type  number:    int
        @param number:    (Optional, def=self.value) Number to convert
        @type  bit_count: int
        @param bit_count: (Optional, def=self.width) Width of bit string

        @rtype:  str
        @return: Bit string
        """
        if not number:
            if type(self.value) in [list, tuple]:
                # We have been given a list to cycle through that is not being mutated...
                if self.cyclic_index == len(self.value):
                    # Reset the index.
                    self.cyclic_index = 0
                number = self.value[self.cyclic_index]
                self.cyclic_index += 1
            else:
                number = self.value

        if not bit_count:
            bit_count = self.width

        return "".join(map(lambda x: str((number >> x) & 1), range(bit_count - 1, -1, -1)))

    # noinspection PyMethodMayBeStatic
    def to_decimal(self, binary):
        """
        Convert a binary string to a decimal number.

        @type  binary: str
        @param binary: Binary string

        @rtype:  int
        @return: Converted bit string
        """

        return int(binary, 2)

    def __len__(self):
        return self.width / 8

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True


class Byte(BitField):
    def __init__(self, value, *args, **kwargs):
        # Inject the one parameter we care to pass in (width)
        width = 8
        max_num = None

        super(Byte, self).__init__(value, width, max_num, *args, **kwargs)

        self.s_type = "byte"

        if type(self.value) not in [int, long, list, tuple]:
            self.value = struct.unpack(self.endian + "B", self.value)[0]


class Word(BitField):
    def __init__(self, value, *args, **kwargs):
        # Inject our width argument
        width = 16
        max_num = None

        super(Word, self).__init__(value, width, max_num, *args, **kwargs)

        self.s_type = "word"

        if type(self.value) not in [int, long, list, tuple]:
            self.value = struct.unpack(self.endian + "H", self.value)[0]


class DWord(BitField):
    def __init__(self, value, *args, **kwargs):
        # Inject our width argument
        width = 32
        max_num = None

        super(DWord, self).__init__(value, width, max_num, *args, **kwargs)

        self.s_type = "dword"

        if type(self.value) not in [int, long, list, tuple]:
            self.value = struct.unpack(self.endian + "L", self.value)[0]


class QWord(BitField):
    def __init__(self, value, *args, **kwargs):
        width = 64
        max_num = None

        super(QWord, self).__init__(value, width, max_num, *args, **kwargs)

        self.s_type = "qword"

        if type(self.value) not in [int, long, list, tuple]:
            self.value = struct.unpack(self.endian + "Q", self.value)[0]
