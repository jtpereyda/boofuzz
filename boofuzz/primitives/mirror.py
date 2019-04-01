from functools import wraps
from .base_primitive import BasePrimitive


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


class Mirror(BasePrimitive):
    """
    Primitive used to keep updated with another primitive.

    Args:
        primitive_name (str):   Name of target primitive.
        request (s_request):    Request this primitive belongs to.
        name (str, optional):   Name of current primitive. Default None.
    """

    def __init__(self, primitive_name, request, name=None):
        super(Mirror, self).__init__()

        self._primitive_name = primitive_name
        self._request = request
        self._name = name
        self._fuzzable = False

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    @property
    def name(self):
        return self._name

    def render(self):
        """
        Render the mirror.

        :return: Rendered value.
        """
        self._rendered = self._render_primitive(self._primitive_name)
        return self._rendered
    
    @property
    def original_value(self):
        return self._original_value_of_primitive(self._primitive_name)

    @_may_recurse
    def _render_primitive(self, primitive_name):
        return self._request.names[primitive_name].render() if primitive_name is not None else None
    
    @_may_recurse
    def _original_value_of_primitive(self, primitive_name):
        return self._request.names[primitive_name].original_value if primitive_name is not None else None