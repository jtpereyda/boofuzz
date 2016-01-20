from .base_primitive import BasePrimitive


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

        self._name = name
        self.values = values

        assert len(self.values) > 0, "You can't have an empty value list for your group!"

        self._value = self._original_value = self.values[0]

        for val in self.values:
            assert isinstance(val, basestring), "Value list may only contain strings or raw data"

    @property
    def name(self):
        return self._name

    def mutate(self):
        """
        Move to the next item in the values list.

        @rtype:  bool
        @return: False
        """
        # TODO: See if num_mutations() can be done away with (me thinks yes).
        if self._mutant_index == self.num_mutations():
            self._fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self._fuzzable or self._fuzz_complete:
            self._value = self._original_value
            return False

        # step through the value list.
        # TODO: break this into a get_value() function, so we can keep mutate as close to standard as possible.
        self._value = self.values[self._mutant_index]

        # increment the mutation count.
        self._mutant_index += 1

        return True

    def num_mutations(self):
        """
        Number of values in this primitive.

        @rtype:  int
        @return: Number of values in this primitive.
        """

        return len(self.values)
