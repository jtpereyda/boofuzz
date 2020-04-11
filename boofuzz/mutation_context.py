import attr


@attr.s
class MutationContext(object):
    """Context for current mutation(s).

    MutationContext objects are created by Session (the fuzz session manager) and passed to various Fuzzable functions
    as needed.

    For complex Fuzzable types that refer to other elements' rendered values, the implementation will typically pass
    the MutationContext along to child/referenced elements to ensure they are rendered properly.
    """
    mutation = attr.ib()
    test_case_context = attr.ib(default=None)
