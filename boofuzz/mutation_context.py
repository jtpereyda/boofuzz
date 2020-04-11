import attr

from .mutation import Mutation
from .test_case_context import TestCaseContext


@attr.s
class MutationContext(object):
    """Context for current mutation(s).

    MutationContext objects are created by Session (the fuzz session manager) and passed to various Fuzzable functions
    as needed.

    For complex Fuzzable types that refer to other elements' rendered values, the implementation will typically pass
    the MutationContext along to child/referenced elements to ensure they are rendered properly.

    Note: Mutations are generated in the context of a Test Case, so a Mutation has a TestCaseContext, but a
    TestCaseContext does not necessarily have a MutationContext.
    """
    mutation = attr.ib(type=Mutation)
    test_case_context = attr.ib(type=TestCaseContext, default=None)
