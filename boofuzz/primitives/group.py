import six

from .base_primitive import BasePrimitive


class Group(BasePrimitive):
    def __init__(self, name, values, default_value=None, encoding="ascii", *args, **kwargs):
        """
        This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
        to a group primitive to specify that the block should cycle through all possible mutations for *each* value
        within the group. The group primitive is useful for example for representing a list of valid opcodes.

        @type  name:            str
        @param name:            Name of group
        @type  values:          list or bytes
        @param values:          List of possible raw values this group can take.

        @param default_value:   Specifying a value when fuzzing() is complete
        @type  encoding:        str
        @param encoding:        (Optional, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
        """
        assert len(values) > 0, "You can't have an empty value list for your group!"
        for val in values:
            assert isinstance(val, (six.binary_type, six.string_types)), "Value list may only contain string/byte types"
        values = list(map(lambda value: value if isinstance(value, bytes) else value.encode(encoding=encoding), values))
        if default_value is not None and not isinstance(default_value, bytes):
            default_value = default_value.encode(encoding=encoding)

        if default_value is None:
            default_value = values[0]

        if default_value in values:
            values.remove(default_value)

        default_value = default_value if isinstance(default_value, bytes) else default_value.encode(encoding=encoding)

        super(Group, self).__init__(name, default_value, *args, **kwargs)

        self.values = values

    def mutations(self, default_value):
        for value in self.values:
            yield value

    def num_mutations(self, default_value):
        """
        Calculate and return the total number of mutations for this individual primitive.

        Args:
            default_value:

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return len(self.values)
