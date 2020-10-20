from functools import wraps

from boofuzz.mutation import Mutation
from .base_primitive import BasePrimitive
from .. import helpers
from ..mutation_context import MutationContext


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

    def __init__(self, name, primitive_name, request, *args, **kwargs):
        super(Mirror, self).__init__(name, default_value=None, *args, **kwargs)

        self._primitive_name = primitive_name
        self._request = request

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def encode(self, value, mutation_context):
        """
        Render the mirror.

        :param value:
        :param mutation_context:
        :return: Rendered value.
        """
        rendered = self._render_primitive(self._primitive_name)
        return helpers.str_to_bytes(rendered)

    def mutations(self, default_value):
        return iter(())  # empty generator

    def original_value(self, test_case_context=None):
        return self._original_value_of_primitive(self._primitive_name, test_case_context)

    @_may_recurse
    def _render_primitive(self, primitive_name):
        return (
            self._request.resolve_name(self.context_path, primitive_name).render(
                mutation_context=MutationContext(Mutation())
            )
            if primitive_name is not None
            else None
        )

    @_may_recurse
    def _original_value_of_primitive(self, primitive_name, test_case_context=None):
        return (
            self._request.resolve_name(self.context_path, primitive_name).original_value(
                test_case_context=test_case_context
            )
            if primitive_name is not None
            else None
        )

    @_may_recurse
    def get_length(self):
        return (
            len(self._request.resolve_name(self.context_path, self._primitive_name))
            if self._primitive_name is not None
            else 0
        )

    def __len__(self):
        return self.get_length()
