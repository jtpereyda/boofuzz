from ..fuzzable import Fuzzable


class Static(Fuzzable):
    def __init__(self, *args, **kwargs):
        super(Static, self).__init__(*args, **kwargs)
