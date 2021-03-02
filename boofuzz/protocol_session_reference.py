import attr


@attr.s
class ProtocolSessionReference(object):
    """Refers to a dynamic value received or generated in the context of an individual test case.

    Pass this object as a primitive's ``default_value`` argument, and make sure you set the referred-to value using
    callbacks, e.g. ``post_test_case_callbacks`` (see :class:`Session <boofuzz.Session>`).

    Args:
        name (str): Refers to a test case session key. Must be set in the
            :class:`ProtocolSession <boofuzz.ProtocolSession>` by the time the value is required in the protocol
            definition. See :class:`Session <boofuzz.Session>`.
        default_value: The default value, used if the element must be rendered outside the context of a test
            case, or sometimes for generating mutations.
    """

    name = attr.ib(type=str)
    default_value = attr.ib()
    pass
