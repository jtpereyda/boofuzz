@attr.s
class TestCaseSessionReference(object):
    """Refers to a dynamic value received or generated in the context of an individual test case.

    Args:
        name (str): Refers to a test case session key. Must be set in the TestCaseContext by the time the value is
            required in the protocol definition. See Session.

    """
    name = attr.ib()
    default_value = attr.ib()
    pass