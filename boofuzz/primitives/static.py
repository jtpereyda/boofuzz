from .. import helpers
from ..fuzzable import Fuzzable


class Static(Fuzzable):
    """Push a static value onto the current block stack.

    :type default_value: Raw
    :param default_value: Raw static data
    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    """

    def __init__(self, default_value, name=None, *args, **kwargs):
        super(Static, self).__init__(name=name, default_value=default_value, fuzzable=False, *args, **kwargs)

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)
