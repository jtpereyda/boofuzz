import attr


@attr.s
class MutationContext(object):
    mutation = attr.ib()
    test_case_context = attr.ib(default=None)
