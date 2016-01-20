from .. import sex
from .. import ifuzzable
from ..primitives.bit_field import BitField


class Repeat(ifuzzable.IFuzzable):
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(self, block_name, request, min_reps=0, max_reps=None, step=1, variable=None, fuzzable=True, name=None):
        """
        Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
        default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
        modifier MUST come after the block it is being applied to.

        @type  block_name: str
        @param block_name: Name of block to apply sizer to
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

        self.block_name = block_name
        self.request = request
        self.variable = variable
        self.min_reps = min_reps
        self.max_reps = max_reps
        self.step = step
        self._fuzzable = fuzzable
        self._name = name

        self._value = ""
        self._original_value = ""  # default to nothing!
        self._rendered = ""  # rendered value
        self._fuzz_complete = False  # flag if this primitive has been completely fuzzed
        self._fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self._mutant_index = 0  # current mutation number
        self.current_reps = min_reps  # current number of repetitions

        # ensure the target block exists.
        if self.block_name not in self.request.names:
            raise sex.SullyRuntimeError(
                    "Can't add repeater for non-existent block: %s!" % self.block_name
            )

        # ensure the user specified either a variable to tie this repeater to or a min/max val.
        if self.variable is None and self.max_reps is None:
            raise sex.SullyRuntimeError(
                    "Repeater for block %s doesn't have a min/max or variable binding!" % self.block_name
            )

        # if a variable is specified, ensure it is an integer type.
        if self.variable and not isinstance(self.variable, BitField):
            print self.variable
            raise sex.SullyRuntimeError(
                    "Attempt to bind the repeater for block %s to a non-integer primitive!" % self.block_name
            )

        # if not binding variable was specified, propagate the fuzz library with the repetition counts.
        if not self.variable:
            self._fuzz_library = range(self.min_reps, self.max_reps + 1, self.step)
        # otherwise, disable fuzzing as the repetition count is determined by the variable.
        else:
            self._fuzzable = False

    @property
    def name(self):
        return self._name

    @property
    def mutant_index(self):
        return self._mutant_index

    @property
    def fuzzable(self):
        return self._fuzzable

    @property
    def original_value(self):
        return self._original_value

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library, return False on completion. If variable-bounding is
        specified then fuzzing is implicitly disabled. Instead, the render() routine will properly calculate the
        correct repetition and return the appropriate data.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # render the contents of the block we are repeating.
        self.request.names[self.block_name].render()

        # if the target block for this sizer is not closed, raise an exception.
        if self.block_name not in self.request.closed_blocks:
            raise sex.SullyRuntimeError(
                    "Can't apply repeater to unclosed block: %s" % self.block_name
            )

        # if we've run out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self._fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self._fuzz_complete:
            self._value = self.original_value
            self.current_reps = self.min_reps
            return False

        if self.variable:
            self.current_reps = self.variable.render()
        else:
            self.current_reps = self._fuzz_library[self.mutant_index]

        # set the current value as a multiple of the rendered block based on the current fuzz library count.
        block = self.request.closed_blocks[self.block_name]
        self._value = block.render() * self._fuzz_library[self.mutant_index]

        # increment the mutation count.
        self._mutant_index += 1

        return True

    def num_mutations(self):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        return len(self._fuzz_library)

    def render(self):
        """
        Nothing fancy on render, simply return the value.
        """

        # if the target block for this sizer is not closed, raise an exception.
        if self.block_name not in self.request.closed_blocks:
            raise sex.SullyRuntimeError("CAN NOT APPLY REPEATER TO UNCLOSED BLOCK: %s" % self.block_name)

        # if a variable-bounding was specified then set the value appropriately.
        if self.variable:
            block = self.request.closed_blocks[self.block_name]
            self._value = block.render() * self.variable.render()

        self._rendered = self._value
        return self._rendered

    def reset(self):
        """
        Reset the fuzz state of this primitive.
        """
        self._fuzz_complete = False
        self._mutant_index = 0
        self._value = self.original_value

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self.current_reps * len(self.request.names[self.block_name])

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
