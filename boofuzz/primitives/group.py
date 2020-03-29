import six

from .base_primitive import BasePrimitive
from ..mutation import Mutation


class Group(BasePrimitive):
    def __init__(self, name, values, default_value=None):
        """
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        @type  name:            str
        @param name:            Name of group
        @type  values:          list or str
        @param values:          List of possible raw values this group can take.

        @param default_value:   Specifying a value when fuzzing() is complete
        """

        super(Group, self).__init__()

        self._name = name
        self.values = values

        assert len(self.values) > 0, "You can't have an empty value list for your group!"

        if default_value is None:
            default_value = self.values[0]
        self._value = self._original_value = default_value

        for val in self.values:
            assert isinstance(val, (six.binary_type, six.string_types)), "Value list may only contain string/byte types"

    def mutations(self):
        """
        """
        if not self._fuzzable:
            return

        for val in self.values:
            yield Mutation(mutations={self.qualified_name: val})

    def encode(self, value, **kwargs):
        return self._render(value)

    def mutations(self):
        for value in self.values:
            yield value

    def num_mutations(self):
        """
        Number of values in this primitive.

        @rtype:  int
        @return: Number of values in this primitive.
        """

        return len(self.values)
