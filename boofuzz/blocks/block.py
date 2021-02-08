from __future__ import absolute_import

from ..fuzzable_block import FuzzableBlock


class Block(FuzzableBlock):
    """The basic building block. Can contain primitives, sizers, checksums or other blocks.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param default_value: Value used when the element is not being fuzzed - should typically represent a valid value,
        defaults to None
    :type default_value: Any, optional
    :param request: Request this block belongs to, defaults to None
    :type request: boofuzz.Request, optional
    :param children: Children of this block, defaults to None
    :type children: boofuzz.Fuzzable, optional
    :param group: Name of group to associate this block with, defaults to None
    :type group: str, optional
    :param encoder: Optional pointer to a function to pass rendered data to prior to return, defaults to None
    :type encoder: callable, optional
    :param dep: Optional primitive whose specific value this block is dependant on, defaults to None
    :type dep: str, optional
    :param dep_value: Value that field "dep" must contain for block to be rendered, defaults to None
    :type dep_value: Any, optional
    :param dep_values: Values that field "dep" may contain for block to be rendered, defaults to None
    :type dep_values: list, optional
    :param dep_compare: Comparison method to apply to dependency (==, !=, >, >=, <, <=), defaults to None
    :type dep_compare: str, optional
    """

    def __init__(
        self,
        name=None,
        default_value=None,
        request=None,
        children=None,
        group=None,
        encoder=None,
        dep=None,
        dep_value=None,
        dep_values=None,
        dep_compare="==",
        *args,
        **kwargs
    ):
        super(Block, self).__init__(
            name=name, default_value=default_value, request=request, children=children, *args, **kwargs
        )

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

    def mutations(self, default_value):
        for item in self.stack:
            self.request.mutant = item
            for mutation in item.get_mutations():
                yield mutation
        if self.group is not None:
            g = self.request.resolve_name(self.context_path, self.group)
            m = list(g.get_mutations())
            for group_mutation in m:
                for item in self.stack:
                    self.request.mutant = item
                    for mutation in item.get_mutations():
                        mutation.mutations[g.qualified_name] = group_mutation.mutations[g.qualified_name]
                        yield mutation

    def num_mutations(self, default_value=None):
        n = super(Block, self).num_mutations(default_value=default_value)
        if self.group is not None:
            n += n * self.request.resolve_name(self.context_path, self.group).get_num_mutations()
        return n

    def _do_dependencies_allow_render(self, mutation_context):
        if self.dep:
            dependent_value = self.request.resolve_name(self.context_path, self.dep).get_value(mutation_context)
            if self.dep_compare == "==":
                if self.dep_values and dependent_value not in self.dep_values:
                    return False
                elif not self.dep_values and dependent_value != self.dep_value:
                    return False

            if self.dep_compare == "!=":
                if self.dep_values and dependent_value in self.dep_values:
                    return False
                elif dependent_value == self.dep_value:
                    return False

            if self.dep_compare == ">" and self.dep_value <= dependent_value:
                return False

            if self.dep_compare == ">=" and self.dep_value < dependent_value:
                return False

            if self.dep_compare == "<" and self.dep_value >= dependent_value:
                return False

            if self.dep_compare == "<=" and self.dep_value > dependent_value:
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
