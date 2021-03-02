import glob
from io import open

from .base_primitive import BasePrimitive


class FromFile(BasePrimitive):
    """Cycles through a list of "bad" values from a file(s).

    Takes filename and open the file(s) to read the values to use in fuzzing process. filename may contain glob
    characters.

    :type  name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  default_value: str
    :param default_value: Default string value
    :type  filename: str
    :param filename: Filename pattern to load all fuzz value
    :type  max_len: int, optional
    :param max_len: Maximum string length, defaults to 0
    :type  fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    def __init__(self, name=None, default_value="", filename=None, max_len=0, *args, **kwargs):

        super(FromFile, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self._filename = filename
        self._fuzz_library = []
        if self._filename is not None:
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
