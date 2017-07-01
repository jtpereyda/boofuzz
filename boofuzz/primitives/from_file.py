import random
import glob

from .base_primitive import BasePrimitive


class FromFile(BasePrimitive):
    # store fuzz_library as a class variable to avoid copying the ~70MB structure across each instantiated primitive.
    _fuzz_library = []

    def __init__(self, value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, max_len=0, name=None, filename=None):
        """
        Primitive that cycles through a list of "bad" values from a file. The primitive take filename and open the file to read
        the values to use in fuzzing process.

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
        @type  filename: str
        @param filename: Filename pattern to load all fuzz value
        """

        super(FromFile, self).__init__()

        self._value = self._original_value = value
        self.size = size
        self.padding = padding
        self.encoding = encoding
        self._fuzzable = fuzzable
        self._name = name
        self._filename = filename
        self.this_library = []
        list_of_files = glob.glob(self._filename)
        for fname in list_of_files:
            _file_handle = open(fname,"r")
            self.this_library.append(_file_handle.readlines())
            _file_handle.close()

        # TODO: Make this more clear
        if max_len > 0:
            # If any of our strings are over max_len
            if any(len(s) > max_len for s in self.this_library):
                # Pull out only the ones that aren't
                self.this_library = list(set([s[:max_len] for s in self.this_library]))

    @property
    def name(self):
        return self._name

    
    def mutate(self):
        """
        Mutate the primitive by stepping through the "this" library, return False on
        completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # loop through the fuzz library until a suitable match is found.
        while 1:
            # if we've ran out of mutations, raise the completion flag.
            if self._mutant_index == self.num_mutations():
                self._fuzz_complete = True

            # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
            if not self._fuzzable or self._fuzz_complete:
                self._value = self._original_value
                return False

            # update the current value from the fuzz library.
            self._value = (self.this_library)[self._mutant_index]

            # increment the mutation count.
            self._mutant_index += 1

            # if the size parameter is disabled, break out of the loop right now.
            if self.size == -1:
                break

            # ignore library items greater then user-supplied length.
            # TODO: might want to make this smarter.
            if len(self._value) > self.size:
                continue

            # pad undersized library items.
            if len(self._value) < self.size:
                self._value += self.padding * (self.size - len(self._value))
                break

        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """
        return len(self.this_library)

    def _render(self, value):
        """Render string value, properly encoded.
        """
        try:
            # Note: In the future, we should use unicode strings when we mean to encode them later. As it is, we need
            # decode the value before decoding it! Meaning we'll never be able to use characters outside the ASCII
            # range.
            _rendered = str(value).decode('ascii').encode(self.encoding)
        except UnicodeDecodeError:
            # If we can't decode the string, just treat it like a plain byte string
            _rendered = value

        return _rendered.rstrip()