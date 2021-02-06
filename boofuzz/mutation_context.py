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

    mutation = attr.ib(type=Mutation)
    protocol_session = attr.ib(type=ProtocolSession, default=None)
