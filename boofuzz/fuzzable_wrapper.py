from boofuzz.mutation import Mutation


class FuzzableWrapper(object):
    name_counter = 0

    def __init__(
            self,
            fuzz_object=None,
            fuzzable=True,
            name=None,
            default_value=None,
    ):
        """

        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        self._fuzzable = fuzzable
        self._name = name
        self._default_value = default_value
        self._fuzz_object = fuzz_object

    @property
    def fuzz_object(self):
        return self._fuzz_object

    @property
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return self._fuzzable

    @property
    def name(self):
        """Element name, should be specific for each instance."""
        if self._name is None:
            FuzzableWrapper.name_counter += 1
            self._name = "{0}{1}".format(type(self).__name__, FuzzableWrapper.name_counter)
        return self._name

    @property
    def qualified_name(self):
        if not hasattr(self, '_context_path'):
            self._context_path = None
        return ".".join(filter(None, (self._context_path, self.name)))

    @property
    def context_path(self):
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x

    @property
    def original_value(self):
        """Original, non-mutated value of element."""
        return self._default_value

    def mutations(self):
        for value in self._fuzz_object.mutations():
            if isinstance(value, Mutation):
                # TODO: Maybe only Block types should be doing this wrapping, as evidenced by needing to do this check
                yield value
                # print(f"Weird, our mutation is already wrapped: {self} {self.qualified_name} ")
            else:
                yield Mutation(mutations={self.qualified_name: value})

    def render_mutated(self, mutation):
        """Render after applying mutation, if applicable."""
        child_data = self._fuzz_object.get_child_data(mutation=mutation)
        if self.qualified_name in mutation.mutations:
            return self._fuzz_object.encode(mutation.mutations[self.qualified_name], child_data=child_data, mutation=mutation)
        else:
            return self._fuzz_object.encode(value=self.original_value, child_data=child_data, mutation=mutation)

    def num_mutations(self):
        return self._fuzz_object.num_mutations()

    def __repr__(self):
        return "<%s <%s> %s %s>" % (self.__class__.__name__, self._fuzz_object, self.name, repr(self._default_value))

    def __len__(self):
        """Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        return len(self._fuzz_object.render_mutated(Mutation()))  # TODO this method might be useless now...

    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return
