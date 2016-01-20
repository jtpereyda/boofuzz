class BasePrimitive(object):
    """
    The primitive base class implements common functionality shared across most primitives.
    """

    def __init__(self):
        self._fuzz_complete = False  # this flag is raised when the mutations are exhausted.
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self.fuzzable = True  # flag controlling whether or not the given primitive is to be fuzzed.
        self.mutant_index = 0  # current mutation index into the fuzz library.
        self.original_value = None  # original value of primitive.
        self._rendered = ""  # rendered value of primitive.
        self._value = None  # current value of primitive.

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library, return False on completion.

        @rtype:  bool
        @return: True on success, False otherwise.
        """
        fuzz_complete = False
        # if we've ran out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self._fuzz_complete = True
            fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or fuzz_complete:
            self._value = self.original_value
            return False

        # update the current value from the fuzz library.
        self._value = self._fuzz_library[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        """
        Calculate and return the total number of mutations for this individual primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take
        """

        return len(self._fuzz_library)

    def render(self):
        """
        Nothing fancy on render, simply return the value.
        """

        self._rendered = self._value
        return self._rendered

    def reset(self):
        """
        Reset this primitive to the starting mutation state.
        """

        self._fuzz_complete = False
        self.mutant_index = 0
        self._value = self.original_value

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, repr(self._value))

    def __len__(self):
        return len(self._value)

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
