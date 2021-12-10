import attr
import collections.abc

from .protocol_session import ProtocolSession


def mutations_list_to_dict(mutations_list_or_dict):
    if isinstance(mutations_list_or_dict, dict):
        return mutations_list_or_dict
    elif isinstance(mutations_list_or_dict, collections.abc.Iterable):
        return {mutation.qualified_name: mutation for mutation in mutations_list_or_dict}
    else:
        raise ValueError("Cannot initialize a MutationContext with mutations {0}".format(mutations_list_or_dict))


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

    mutations = attr.ib(factory=dict, converter=mutations_list_to_dict)  # maps qualified names to a Mutation
    message_path = attr.ib(factory=list)
    protocol_session = attr.ib(type=ProtocolSession, default=None)
