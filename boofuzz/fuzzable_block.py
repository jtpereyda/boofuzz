from .fuzzable import Fuzzable
from .fuzzable_wrapper import FuzzableWrapper


class FuzzableBlock(Fuzzable):
    """Fuzzable type designed to have children elements. Overrides basic Fuzzable functions and adds push()."""

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
        rendered = b""
        for item in self.stack:
            rendered += item.render_mutated(mutation_context=mutation_context)
        return rendered

    def push(self, item):
        """Push a child element onto this block's stack.
        
        Args:
            item (FuzzableWrapper): Some wrapped Fuzzable element

        Returns: None
        """
        self.stack.append(item)
