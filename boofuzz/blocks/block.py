from __future__ import absolute_import

from .. import helpers
from ..ifuzzable import IFuzzable


class Block(IFuzzable):
    def __init__(
        self, name, request, group=None, encoder=None, dep=None, dep_value=None, dep_values=None, dep_compare="=="
    ):
        """
        The basic building block. Can contain primitives, sizers, checksums or other blocks.

        @type  name:        str
        @param name:        Name of the new block
        @type  request:     Request
        @param request:     Request this block belongs to
        @type  group:       str
        @param group:       (Optional, def=None) Name of group to associate this block with
        @type  encoder:     Function Pointer
        @param encoder:     (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
        @type  dep:         str
        @param dep:         (Optional, def=None) Optional primitive whose specific value this block is dependant on
        @type  dep_value:   Mixed
        @param dep_value:   (Optional, def=None) Value that field "dep" must contain for block to be rendered
        @type  dep_values:  List of Mixed Types
        @param dep_values:  (Optional, def=[]) Values that field "dep" may contain for block to be rendered
        @type  dep_compare: str
        @param dep_compare: (Optional, def="==") Comparison method to apply to dependency (==, !=, >, >=, <, <=)
        """

        self._name = name
        self.request = request
        self.group = group
        self.encoder = encoder
        self.dep = dep
        self.dep_value = dep_value
        self.dep_values = dep_values
        self.dep_compare = dep_compare

        self.stack = []  # block item stack.
        self._rendered = b""  # rendered block contents.
        self._fuzzable = True  # blocks are always fuzzable because they may contain fuzzable items.
        self.group_idx = 0  # if this block is tied to a group, the index within that group.
        self._fuzz_complete = False  # whether or not we are done fuzzing this block.
        self._mutant_index = 0  # current mutation index.
        self._element_mutant_index = None  # index of current mutant element within self.stack

    @property
    def mutant_index(self):
        return self._mutant_index

    @property
    def fuzzable(self):
        return self._fuzzable

    @property
    def original_value(self):
        original_value = b""

        for item in self.stack:
            original_value += helpers.str_to_bytes(item.original_value)

        return original_value

    @property
    def name(self):
        return self._name

    def mutate(self):
        if self._element_mutant_index is None:
            self._element_mutant_index = 0

        mutated = False

        # are we done with this block?
        if self._fuzz_complete:
            return False

        #
        # mutate every item on the stack for every possible group value.
        #
        if self.group:
            group_count = self.request.names[self.group].num_mutations()

            # update the group value to that at the current index.
            self.request.names[self.group]._value = self.request.names[self.group].values[self.group_idx]

            # mutate every item on the stack at the current group value.
            while self._element_mutant_index < len(self.stack):
                item = self.stack[self._element_mutant_index]
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item
                    break
                else:
                    self._element_mutant_index += 1

            # if the possible mutations for the stack are exhausted.
            if not mutated:
                # increment the group value index.
                self.group_idx += 1

                # if the group values are exhausted, we are done with this block.
                if self.group_idx == group_count:
                    # restore the original group value.
                    self.request.names[self.group].reset()

                # otherwise continue mutating this group/block.
                else:
                    # update the group value to that at the current index.
                    self.request.names[self.group]._value = self.request.names[self.group].values[self.group_idx]

                    # this the mutate state for every item in this blocks stack.
                    # NOT THE BLOCK ITSELF THOUGH! (hence why we didn't call self.reset())
                    for item in self.stack:
                        if item.fuzzable:
                            item.reset()

                    # now mutate the first field in this block before continuing.
                    # (we repeat a test case if we don't mutate something)
                    self._element_mutant_index = 0
                    while self._element_mutant_index < len(self.stack):
                        item = self.stack[self._element_mutant_index]
                        if item.fuzzable and item.mutate():
                            mutated = True

                            if not isinstance(item, Block):
                                self.request.mutant = item

                            break
                        else:
                            self._element_mutant_index += 1
        #
        # no grouping, mutate every item on the stack once.
        #
        else:
            while self._element_mutant_index < len(self.stack):
                item = self.stack[self._element_mutant_index]
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item

                    break
                else:
                    self._element_mutant_index += 1

        # if this block is dependant on another field, then manually update that fields value appropriately while we
        # mutate this block. we'll restore the original value of the field prior to continuing.
        if mutated and self.dep:
            # if a list of values was specified, use the first item in the list.
            if self.dep_values:
                self.request.names[self.dep]._value = self.dep_values[0]

            # if a list of values was not specified, assume a single value is present.
            else:
                self.request.names[self.dep]._value = self.dep_value

        # we are done mutating this block.
        if not mutated:
            self._fuzz_complete = True

            # if we had a dependency, make sure we restore the original value.
            if self.dep:
                self.request.names[self.dep].reset()

        return mutated

    def skip_element(self):
        item = self.stack[self._element_mutant_index]
        if isinstance(item, Block):
            item.skip_element()
        else:
            item.reset()
            self._element_mutant_index += 1

    def num_mutations(self):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

        # if this block is associated with a group, then multiply out the number of possible mutations.
        if self.group:
            num_mutations *= len(self.request.names[self.group].values)

        return num_mutations

    def push(self, item):
        """
        Push an arbitrary item onto this blocks stack.
        @type item: BasePrimitive | Block | boofuzz.blocks.size.Size | boofuzz.blocks.repeat.Repeat
        @param item: Some primitive/block/etc.
        """

        self.stack.append(item)

    def render(self):
        """
        Step through every item on this blocks stack and render it. Subsequent blocks recursively render their stacks.
        """

        #
        # if this block is dependant on another field and the value is not met, render nothing.
        #
        self._rendered = b""

        if self.dep:
            if self.dep_compare == "==":
                if self.dep_values and self.request.names[self.dep]._value not in self.dep_values:
                    return self._rendered

                elif not self.dep_values and self.request.names[self.dep]._value != self.dep_value:
                    return self._rendered

            if self.dep_compare == "!=":
                if self.dep_values and self.request.names[self.dep]._value in self.dep_values:
                    return self._rendered

                elif self.request.names[self.dep]._value == self.dep_value:
                    return

            if self.dep_compare == ">" and self.dep_value <= self.request.names[self.dep]._value:
                return self._rendered

            if self.dep_compare == ">=" and self.dep_value < self.request.names[self.dep]._value:
                return self._rendered

            if self.dep_compare == "<" and self.dep_value >= self.request.names[self.dep]._value:
                return self._rendered

            if self.dep_compare == "<=" and self.dep_value > self.request.names[self.dep]._value:
                return self._rendered

        #
        # otherwise, render and encode as usual.
        #

        for item in self.stack:
            self._rendered += item.render()

        # add the completed block to the request dictionary.
        self.request.closed_blocks[self.name] = self

        # if an encoder was attached to this block, call it.
        if self.encoder:
            self._rendered = self.encoder(self._rendered)

        return helpers.str_to_bytes(self._rendered)

    def reset(self):
        """
        Reset the primitives on this blocks stack to the starting mutation state.
        """

        self._fuzz_complete = False
        self.group_idx = 0
        self._element_mutant_index = None

        for item in self.stack:
            if item.fuzzable:
                item.reset()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        if self.encoder is not None:
            return len(self.render())
        else:
            return sum(len(item) for item in self.stack)

    def __bool__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
