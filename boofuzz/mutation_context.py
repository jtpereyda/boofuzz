import attr


@attr.s
class MutationContext(object):
    mutation = attr.ib()
    test_case_session = attr.ib(factory=dict)
