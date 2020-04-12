from .fuzzable import Fuzzable
from .fuzzable_wrapper import FuzzableWrapper


class FuzzableBlock(Fuzzable):
    """Fuzzable type designed to have children elements.

    Overrides basic Fuzzable functions and adds:
    1. push()
    2. get_child_data()
    """

    def __init__(self, request):
        super().__init__()
        self.stack = []  # block item stack
        self.request = request

    def mutations(self):
        for item in self.stack:
            self.request.mutant = item
            for mutation in item.mutations():
                yield mutation

    def num_mutations(self, default_value=None):
        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

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
            item (FuzzableWrapper): Some wrapped Fuzzable element

        Returns: None
        """
        self.stack.append(item)
