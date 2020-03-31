import attr

from boofuzz.mutation import Mutation
from boofuzz.mutation_context import MutationContext


@attr.s
class ReferenceValueTestCaseSession(object):
    name = attr.ib()
    pass


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
        Internal object used to handle Fuzzable objects. Manages name, default value, etc.

        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:          str
        @param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
        """
        self._fuzzable = fuzzable
        self._name = name
        self._default_value = default_value
        self._fuzz_object = fuzz_object
        self._context_path = ""

    @property
    def fuzz_object(self):
        return self._fuzz_object

    @property
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return self._fuzzable

    @property
    def name(self):
        """Element name, should be unique for each instance.

        :rtype: str
        """
        if self._name is None:
            FuzzableWrapper.name_counter += 1
            self._name = "{0}{1}".format(type(self).__name__, FuzzableWrapper.name_counter)
        return self._name

    @property
    def qualified_name(self):
        return ".".join(
            s for s in (self._context_path, self.name) if s != ""
        )

    @property
    def context_path(self):
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x

    def original_value(self, mutation_context):
        """Original, non-mutated value of element."""
        if isinstance(self._default_value, ReferenceValueTestCaseSession):
            return mutation_context.test_case_session[ReferenceValueTestCaseSession.name]
        else:
            return self._default_value

    def mutations(self):
        for value in self._fuzz_object.mutations():
            if isinstance(value, Mutation):
                yield value
            else:
                yield Mutation(mutations={self.qualified_name: value})

    def render_mutated(self, mutation_context):
        """Render after applying mutation, if applicable.
        :type mutation_context: MutationContext
        """
        child_data = self._fuzz_object.get_child_data(mutation_context=mutation_context)
        if self.qualified_name in mutation_context.mutation.mutations:
            return self._fuzz_object.encode(mutation_context.mutation.mutations[self.qualified_name],
                                            child_data=child_data, mutation_context=mutation_context)
        else:
            return self._fuzz_object.encode(value=self.original_value(mutation_context=mutation_context),
                                            child_data=child_data,
                                            mutation_context=mutation_context)

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
