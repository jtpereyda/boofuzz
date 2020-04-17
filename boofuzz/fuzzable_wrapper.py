from collections import Iterable

from boofuzz.mutation import Mutation
from future.moves import itertools

from .mutation_context import MutationContext
from .test_case_context import TestCaseContext
from .test_case_session_reference import TestCaseSessionReference
from .mutator import Mutator


class FuzzNode(object):
    name_counter = 0

    def __init__(self, mutator=None, name=None, default_value=None, fuzzable=True, fuzz_values=None, children=None):
        """Internal object used to handle Fuzzable objects. Manages context like name, default value, etc.

        Args:
            mutator (Mutator): Fuzzable element.
            fuzzable (bool): Enable fuzzing of this primitive. Default: True.
            name (str): Name, for referencing later. Names should always be provided, but if not, a default name will
                be given.
            default_value: Can be a static value, or a ReferenceValueTestCaseSession.
            fuzz_values (list): List of custom fuzz values to add to the normal mutations.
            children (Iterable): List of child nodes (typically given to FuzzableBlock types).
        """
        self._fuzzable = fuzzable
        self._name = name
        self._default_value = default_value
        self._fuzz_object = mutator
        self._context_path = ""
        self._request = None
        self._halt_mutations = False
        if fuzz_values is None:
            fuzz_values = list()
        self._fuzz_values = fuzz_values
        if children is not None:
            self.fuzz_object.stack = list(children)

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
            FuzzNode.name_counter += 1
            self._name = "{0}{1}".format(type(self.fuzz_object).__name__, FuzzNode.name_counter)
        return self._name

    @property
    def qualified_name(self):
        return ".".join(s for s in (self._context_path, self.name) if s != "")

    @property
    def context_path(self):
        """The path of parent elements leading to this element. E.g. "myrequest.myblock1.myblock2".

        Set by the session manager (Session).

        Returns:
            str: Context path, dot-delimited.

        """
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x
        self._fuzz_object.context_path = x

    @property
    def request(self):
        """Reference to the Request in which this FuzzableWrapper lives."""
        return self._request

    @request.setter
    def request(self, x):
        self._request = x
        self._fuzz_object.request = x

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

    def mutations(self):
        try:
            for value in itertools.chain(self._fuzz_object.mutations(self.original_value()), self._fuzz_values):
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
        return self._fuzz_object.encode(
            value=self.get_value(mutation_context=mutation_context), mutation_context=mutation_context
        )

    def get_value(self, mutation_context=None):
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

    def num_mutations(self):
        return self._fuzz_object.num_mutations(default_value=self.original_value(test_case_context=None))

    def __repr__(self):
        return "<%s <%s> %s %s>" % (
            self.__class__.__name__,
            self._fuzz_object,
            self.name,
            repr(self.original_value(test_case_context=None)),
        )

    def __len__(self):
        """Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        return len(self._fuzz_object.render_mutated(Mutation()))

    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return True
