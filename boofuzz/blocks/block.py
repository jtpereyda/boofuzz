from __future__ import absolute_import

from .. import helpers
from ..fuzzable_block import FuzzableBlock
from ..mutation import Mutation


class Block(FuzzableBlock):
    def __init__(self, name, default_value=None, request=None, group=None, encoder=None, dep=None, dep_value=None, dep_values=None, dep_compare="==", *args, **kwargs):
        """
        The basic building block. Can contain primitives, sizers, checksums or other blocks.

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
        super(Block, self).__init__(name=name, default_value=default_value, request=request, *args, **kwargs)

        self.request = request
        self.group = group
        self.encoder = encoder
        self.dep = dep
        self.dep_value = dep_value
        self.dep_values = dep_values
        self.dep_compare = dep_compare

        self._rendered = b""  # rendered block contents.
        self.group_idx = 0  # if this block is tied to a group, the index within that group.
        self._fuzz_complete = False  # whether or not we are done fuzzing this block.
        self._mutant_index = 0  # current mutation index.

    def mutate(self):  # TODO salvage the group reference behavior from this deprecated method
        mutated = False

        # are we done with this block?
        if self._fuzz_complete:
            return False

        #
        # mutate every item on the stack for every possible group value.
        #
        if self.group:
            group_count = self.request.names[self.group].get_num_mutations()

            # update the group value to that at the current index.
            self.request.names[self.group]._value = self.request.names[self.group].values[self.group_idx]

            # mutate every item on the stack at the current group value.
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item
                    break

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
                    for item in self.stack:
                        if item.fuzzable and item.mutate():
                            mutated = True

                            if not isinstance(item, Block):
                                self.request.mutant = item

                            break
        #
        # no grouping, mutate every item on the stack once.
        #
        else:
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item

                    break

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

    def num_mutations(self, default_value=None):
        n = super(Block, self).num_mutations(default_value=default_value)
        if self.group:
            n *= len(self.request.names[self.group].get_num_mutations())
        return n

    def _do_dependencies_allow_render(self, mutation_context):
        if self.dep:
            if self.dep_compare == "==":
                if self.dep_values and self.request.names[self.dep].get_value(mutation_context) not in self.dep_values:
                    return False
                elif not self.dep_values and self.request.names[self.dep].get_value(mutation_context) != self.dep_value:
                    return False

            if self.dep_compare == "!=":
                if self.dep_values and self.request.names[self.dep].get_value(mutation_context) in self.dep_values:
                    return False
                elif self.request.names[self.dep].get_value(mutation_context) == self.dep_value:
                    return False

            if self.dep_compare == ">" and self.dep_value <= self.request.names[self.dep].get_value(mutation_context):
                return False

            if self.dep_compare == ">=" and self.dep_value < self.request.names[self.dep].get_value(mutation_context):
                return False

            if self.dep_compare == "<" and self.dep_value >= self.request.names[self.dep].get_value(mutation_context):
                return False

            if self.dep_compare == "<=" and self.dep_value > self.request.names[self.dep].get_value(mutation_context):
                return False
        return True

    def encode(self, value, mutation_context):
        if self._do_dependencies_allow_render(mutation_context=mutation_context):
            child_data = super(Block, self).get_child_data(mutation_context=mutation_context)
        else:
            child_data = b""
        if self.encoder:
            return self.encoder(child_data)
        else:
            return child_data
