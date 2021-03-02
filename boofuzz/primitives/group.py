import six

from .base_primitive import BasePrimitive


class Group(BasePrimitive):
    """This primitive represents a list of static values, stepping through each one on mutation.

    You can tie a block
    to a group primitive to specify that the block should cycle through all possible mutations for *each* value
    within the group. The group primitive is useful for example for representing a list of valid opcodes.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param values: List of possible raw values this group can take.
    :type values: list of bytes or list of str
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value,
        defaults to None
    :type default_value: str, optional
    :param encoding: String encoding, ex: utf_16_le for Microsoft Unicode, defaults to ascii
    :type encoding: str, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    :type fuzzable: bool, optional
    """

    def __init__(self, name=None, values=None, default_value=None, encoding="ascii", *args, **kwargs):
        assert len(values) > 0, "You can't have an empty value list for your group!"
        for val in values:
            assert isinstance(val, (six.binary_type, six.string_types)), "Value list may only contain string/byte types"
        values = list(map(lambda value: value if isinstance(value, bytes) else value.encode(encoding=encoding), values))

        if default_value is None:
            default_value = values[0]

        default_value = default_value if isinstance(default_value, bytes) else default_value.encode(encoding=encoding)

        if default_value in values:
            values.remove(default_value)

        super(Group, self).__init__(name=name, default_value=default_value, *args, **kwargs)

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
