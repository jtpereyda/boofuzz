import attr

from .mutation import Mutation
from .protocol_session import ProtocolSession


@attr.s
class MutationContext(object):
    """Context for current mutation(s).

    MutationContext objects are created by Session (the fuzz session manager) and passed to various Fuzzable functions
    as needed.

    For complex Fuzzable types that refer to other elements' rendered values, the implementation will typically pass
    the MutationContext along to child/referenced elements to ensure they are rendered properly.

    Note: Mutations are generated in the context of a Test Case, so a Mutation has a ProtocolSession, but a
    ProtocolSession does not necessarily have a MutationContext.
    """

    mutations = attr.ib(factory=dict)  # maps qualified names to a Mutation
    message_path = attr.ib(factory=list)
    protocol_session = attr.ib(type=ProtocolSession, default=None)

    def merge_in(self, *mutations):
        """Merge Mutation objects into this Mutation.

        Args:
            *args (Mutation): Mutation objects to merge in

        Returns:
            MutationContext: self
        """
        for mutation in mutations:
            # if self.message_path != mutation.message_path:
            #     raise ValueError("Cannot merge Mutation objects with differing message paths")
            self.mutations.update(mutation.mutations)
        return self
