from .base_primitive import BasePrimitive


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

        self._fuzz_complete = True
        self._fuzzable = False
        self._value = self._original_value = value
        self._name = name

    @property
    def name(self):
        return self._name

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
