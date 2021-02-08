from .fuzzable import Fuzzable


class FuzzableBlock(Fuzzable):
    """Fuzzable type designed to have children elements.

    FuzzableBlock overrides the following methods, changing the default behavior for any type based on FuzzableBlock:

    1. :meth:`mutations` Iterate through the mutations yielded by all child nodes.
    2. :meth:`num_mutations` Sum the mutations represented by each child node.
    3. :meth:`encode` Call :meth:`get_child_data`.

    FuzzableBlock adds the following methods:

    1. :meth:`get_child_data` Render and concatenate all child nodes.
    2. :meth:`push` Add an additional child node; generally used only internally.

    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type name: str, optional
    :param request: Request this block belongs to, defaults to None
    :type request: boofuzz.Request, optional
    :param children: List of child nodes (typically given to FuzzableBlock types)m defaults to None
    :type children: boofuzz.Fuzzable, optional
    """

    def __init__(self, name=None, request=None, children=None, *args, **kwargs):
        super(FuzzableBlock, self).__init__(name=name, *args, **kwargs)
        self.request = request

        if children is None:
            self.stack = []
        elif isinstance(children, Fuzzable):
            self.stack = [children]
        else:
            self.stack = list(children)

    def mutations(self, default_value):
        for item in self.stack:
            self.request.mutant = item
            for mutation in item.get_mutations():
                yield mutation

    def num_mutations(self, default_value=None):
        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.get_num_mutations()

        return num_mutations

    def get_child_data(self, mutation_context):
        """Get child or referenced data for this node.

        For blocks that reference other data from the message structure (e.g. size, checksum, blocks). See
        FuzzableBlock for an example.

        Args:
            mutation_context (MutationContext): Mutation context.

        Returns:
            bytes: Child data.
        """
        rendered = b""
        for item in self.stack:
            rendered += item.render(mutation_context=mutation_context)
        return rendered

    def encode(self, value, mutation_context):
        return self.get_child_data(mutation_context=mutation_context)

    def push(self, item):
        """Push a child element onto this block's stack.

        Args:
            item (Fuzzable): Some wrapped Fuzzable element

        Returns: None
        """
        self.stack.append(item)
