import glob
from io import open

from .base_primitive import BasePrimitive


class FromFile(BasePrimitive):
    def __init__(self, value, fuzzable=True, max_len=0, name=None, filename=None):
        """
        Cycles through a list of "bad" values from a file(s). Takes filename and open the file(s) to read
        the values to use in fuzzing process. filename may contain glob characters.

        @type  value:    str
        @param value:    Default string value
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
        self._fuzzable = fuzzable
        self._name = name
        self._filename = filename
        self._fuzz_library = []
        list_of_files = glob.glob(self._filename)
        for fname in list_of_files:
            with open(fname, "rb") as _file_handle:
                self._fuzz_library.extend(list(filter(None, _file_handle.read().splitlines())))

        # TODO: Make this more clear
        if max_len > 0:
            # If any of our strings are over max_len
            if any(len(s) > max_len for s in self._fuzz_library):
                # Pull out only the ones that aren't
                self._fuzz_library = list(set([s for s in self._fuzz_library if len(s) <= max_len]))

    @property
    def name(self):
        return self._name
