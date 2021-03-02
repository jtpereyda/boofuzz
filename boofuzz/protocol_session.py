import attr


@attr.s
class ProtocolSession(object):
    """Contains a ``session_variables`` dictionary used to store data specific to a single fuzzing test case.

    Generally, values in ``session_variables`` will be set in a callback function, e.g. ``post_test_case_callbacks``
    (see :class:`Session <boofuzz.Session>`). Variables may be used in a later callback function, or by a
    :class:`ProtocolSessionReference <boofuzz.ProtocolSessionReference>` object.
    """

    session_variables = attr.ib(factory=dict)
    previous_message = attr.ib(default=None)
    current_message = attr.ib(default=None)
