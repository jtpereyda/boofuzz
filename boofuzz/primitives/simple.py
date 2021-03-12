from ..fuzzable import Fuzzable


class Simple(Fuzzable):
    """Simple bytes value with manually specified fuzz values only.

    :type name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type default_value: Raw, optional
    :param default_value: Raw static data
    :type fuzz_values: list, optional
    :param fuzz_values: List of fuzz values, defaults to None. If empty, Simple is equivalent to Static.
    :type  fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this primitive, defaults to true
    """

    def __init__(self, name=None, default_value=None, fuzz_values=None, *args, **kwargs):
        super(Simple, self).__init__(name=name, default_value=default_value, fuzz_values=fuzz_values, *args, **kwargs)
