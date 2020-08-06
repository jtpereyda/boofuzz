from past.builtins import range

from .. import helpers
from ..fuzzable import Fuzzable
from ..protocol_session_reference import ProtocolSessionReference


class Repeat(Fuzzable):
    """
    Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
    default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
    modifier MUST come after the block it is being applied to.

    @type  block_name: str
    @param block_name: Name of block to repeat
    @type  request:    s_request
    @param request:    Request this block belongs to
    @type  min_reps:   int
    @param min_reps:   (Optional, def=0) Minimum number of block repetitions
    @type  max_reps:   int
    @param max_reps:   (Optional, def=None) Maximum number of block repetitions
    @type  step:       int
    @param step:       (Optional, def=1) Step count between min and max reps
    @type  variable:   Sulley Integer Primitive
    @param variable:   (Optional, def=None) Repetitions will be derived from this variable, disables fuzzing
    @type  fuzzable:   bool
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       str
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    def __init__(
        self,
        name,
        block_name,
        request,
        min_reps=0,
        max_reps=None,
        step=1,
        variable=None,
        fuzzable=True,
        default_value=None,
        *args,
        **kwargs
    ):
        if default_value is None:
            if variable is not None:
                default_value = ProtocolSessionReference(name=variable, default_value=0)
            else:
                default_value = 0

        super(Repeat, self).__init__(name, default_value, *args, **kwargs)

        self.block_name = block_name
        self.request = request
        self.min_reps = min_reps
        self.max_reps = max_reps
        self.step = step
        self._fuzzable = fuzzable
        self._name = name

        self._value = b""
        self._original_value = b""  # default to nothing!
        self._rendered = b""  # rendered value
        self._fuzz_complete = False  # flag if this primitive has been completely fuzzed
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self._mutant_index = 0  # current mutation number
        self.current_reps = min_reps  # current number of repetitions

        if self.max_reps is not None:
            self._fuzz_library = range(self.min_reps, self.max_reps + 1, self.step)

    @property
    def fuzzable(self):
        return self._fuzzable

    def mutations(self, default_value):
        for fuzzed_reps_number in self._fuzz_library:
            yield fuzzed_reps_number

    def num_mutations(self, default_value):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        :param default_value:
        """
        return len(self._fuzz_library)

    def encode(self, value, mutation_context):
        return value * self._get_child_data(mutation_context=mutation_context)

    def _get_child_data(self, mutation_context):
        _rendered = self.request.resolve_name(self.context_path, self.block_name).render(
            mutation_context=mutation_context
        )
        return helpers.str_to_bytes(_rendered)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self.current_reps * len(self.request.names[self.block_name])
