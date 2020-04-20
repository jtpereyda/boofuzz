from collections import Iterable

from boofuzz.mutation import Mutation
from future.moves import itertools

from .mutation_context import MutationContext
from .test_case_context import TestCaseContext
from .test_case_session_reference import TestCaseSessionReference
from typing import Union
from future.builtins import object


class Fuzzable(object):
    name_counter = 0

    def __init__(self, name=None, default_value=None, fuzzable=True, fuzz_values=None):
        """Internal object used to handle Fuzzable objects. Manages context like name, default value, etc.

        Args:
            fuzzable (bool): Enable fuzzing of this primitive. Default: True.
            name (str): Name, for referencing later. Names should always be provided, but if not, a default name will
                be given.
            default_value: Can be a static value, or a ReferenceValueTestCaseSession.
            fuzz_values (list): List of custom fuzz values to add to the normal mutations.
        """
        self._fuzzable = fuzzable
        self._name = name
        self._default_value = default_value
        self._context_path = ""
        self._request = None
        self._halt_mutations = False
        if fuzz_values is None:
            fuzz_values = list()
        self._fuzz_values = fuzz_values

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
            Fuzzable.name_counter += 1
            self._name = "{0}{1}".format(type(self).__name__, Fuzzable.name_counter)
        return self._name

    @property
    def qualified_name(self):
        return ".".join(s for s in (self._context_path, self.name) if s != "")

    @property
    def context_path(self):
        """Dot-delimited string that describes the path up to this element. Configured after the object is attached
        to a Request."""
        if not hasattr(self, "_context_path"):
            self._context_path = None
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x

    @property
    def request(self):
        """Reference to the Request to which this object is attached."""
        if not hasattr(self, "_request"):
            self._request = None
        return self._request

    @request.setter
    def request(self, x):
        self._request = x

    def stop_mutations(self):
        """Stop yielding mutations on the currently running :py:meth:`mutations` call.

        Used by boofuzz to stop fuzzing an element when it's already caused several failures.

        Returns:
            NoneType: None
        """
        self._halt_mutations = True

    def original_value(self, test_case_context=None):
        """Original, non-mutated value of element.

        Args:
            test_case_context (TestCaseContext): Used to resolve ReferenceValueTestCaseSession type default values.

        Returns:
        """
        if isinstance(self._default_value, TestCaseSessionReference):
            if test_case_context is None:
                return self._default_value.default_value
            else:
                return test_case_context.session_variables[self._default_value.name]
        else:
            return self._default_value

    def get_mutations(self):
        try:
            for value in itertools.chain(self.mutations(self.original_value()), self._fuzz_values):
                if self._halt_mutations:
                    self._halt_mutations = False
                    return
                if isinstance(value, Mutation):
                    yield value
                else:
                    yield Mutation(mutations={self.qualified_name: value})
        finally:
            self._halt_mutations = False  # in case stop_mutations is called when mutations were exhausted anyway

    def render(self, mutation_context=None):
        """Render after applying mutation, if applicable.
        :type mutation_context: MutationContext
        """
        return self.encode(value=self.get_value(mutation_context=mutation_context), mutation_context=mutation_context)

    def get_value(self, mutation_context=None):
        """

        Args:
            mutation_context (MutationContext):

        Returns:

        """
        if mutation_context is None:
            mutation_context = MutationContext(Mutation())
        if self.qualified_name in mutation_context.mutation.mutations:
            mutation = mutation_context.mutation.mutations[self.qualified_name]
            if callable(mutation):
                value = mutation(self.original_value(test_case_context=mutation_context.test_case_context))
            else:
                value = mutation
        else:
            value = self.original_value(test_case_context=mutation_context.test_case_context)

        return value

    def get_num_mutations(self):
        return self.num_mutations(default_value=self.original_value(test_case_context=None))

    def mutations(self, default_value):
        """Generator to yield mutation values for this element.

        Values are either plain values or callable functions that take a "default value" and mutate it. Functions are
        used when the default or "normal" value influences the fuzzed value. Functions are used because the "normal"
        value is sometimes dynamic and not known at the time of generation.

        Each mutation should be a pre-rendered value. That is, it must be suitable to pass to encode().

        Default: Empty iterator.

        Args:
            default_value:
        """
        return
        yield

    def encode(self, value, mutation_context):
        """Takes a value and encodes/renders/serializes it to a bytes (byte string).

        Optional if mutations() yields bytes.

        Example: Yield strings with mutations() and encode them to UTF-8 using encode().

        Default behavior: Return value.

        Args:
            value: Value to encode. Type should match the type yielded by mutations()
            mutation_context (MutationContext): Context for current mutation, if any.


        Returns:
            bytes: Encoded/serialized value.
        """
        return value

    def num_mutations(self, default_value):
        """Return the total number of mutations for this element.

        Default implementation exhausts the mutations() generator, which is inefficient. Override if you can provide a
        value more efficiently, or if exhausting the mutations() generator has side effects.

        Args:
            default_value: Use if number of mutations depends on the default value. Provided by FuzzableWrapper.
                Note: It is generally good behavior to have a consistent number of mutations for a given default value
                length.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return sum(1 for _ in self.mutations(default_value=default_value))

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, repr(self.original_value(test_case_context=None)),)

    def __len__(self):
        """Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        return len(self.render(MutationContext(mutation=Mutation())))

    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return True
