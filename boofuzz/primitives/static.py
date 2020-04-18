from ..fuzzable_wrapper import FuzzNode


class Static(FuzzNode):
    def __init__(self, *args, **kwargs):
        super(Static, self).__init__(*args, **kwargs)
