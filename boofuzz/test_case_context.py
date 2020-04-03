import attr


@attr.s
class TestCaseContext(object):
    session_variables = attr.ib(factory=dict)
