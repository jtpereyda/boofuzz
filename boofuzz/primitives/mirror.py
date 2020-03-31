from functools import wraps

from .base_primitive import BasePrimitive
from .. import helpers
from ..mutation import Mutation


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
    """

    def __init__(self, primitive_name, request):
        super(Mirror, self).__init__()

        self._primitive_name = primitive_name
        self._request = request

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def encode(self, value, child_data, mutation_context=None):
        """
        Render the mirror.

        :param mutation_context:
        :return: Rendered value.
        """
        _ = value
        rendered = self._render_primitive(self._primitive_name)
        return helpers.str_to_bytes(rendered)

    def mutations(self):
        return iter(())  # empty generator
    
    def original_value(self, mutation_context):
        return self._original_value_of_primitive(self._primitive_name, mutation_context)

    @_may_recurse
    def _render_primitive(self, primitive_name):
        return self._request.names[primitive_name].render_mutated(Mutation()) if primitive_name is not None else None

    @_may_recurse
    def _original_value_of_primitive(self, primitive_name, mutation_context):
        if primitive_name is None:
            return None
        else:
            return self._request.names[primitive_name].original_value(mutation_context=mutation_context)

    @_may_recurse
    def get_length(self):
        return len(self._request.names[self._primitive_name]) if self._primitive_name is not None else 0

    def __len__(self):
        return self.get_length()
