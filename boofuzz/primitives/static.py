from .. import helpers
from ..fuzzable import Fuzzable


class Static(Fuzzable):
    def __init__(self, *args, **kwargs):
        super(Static, self).__init__(*args, **kwargs)

    def encode(self, value, mutation_context):
        if value is None:
            value = b""
        return helpers.str_to_bytes(value)
