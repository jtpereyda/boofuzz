from builtins import object
from future.utils import listitems, with_metaclass

from .mutation_context import MutationContext


class DocStringInheritor(type):
    """
    A variation on
    http://groups.google.com/group/comp.lang.python/msg/26f7b4fcb4d66c95
    by Paul McGuire
    """

    def __new__(meta, name, bases, clsdict):
        if not ("__doc__" in clsdict and clsdict["__doc__"]):
            for mro_cls in (mro_cls for base in bases for mro_cls in base.mro()):
                doc = mro_cls.__doc__
                if doc:
                    clsdict["__doc__"] = doc
                    break
        for attr, attribute in listitems(clsdict):
            if not attribute.__doc__:
                for mro_cls in (mro_cls for base in bases for mro_cls in base.mro() if hasattr(mro_cls, attr)):
                    doc = getattr(getattr(mro_cls, attr), "__doc__")
                    if doc:
                        if isinstance(attribute, property):
                            clsdict[attr] = property(attribute.fget, attribute.fset, attribute.fdel, doc)
                        else:
                            attribute.__doc__ = doc
                        break
        return type.__new__(meta, name, bases, clsdict)


# DocStringInheritor is the metaclass in python 2 and 3
class Fuzzable(with_metaclass(DocStringInheritor, object)):
    """Base class for fuzzable message element types.

    A typical Fuzzable type will implement mutations() (a generator) or encode() or both.

    num_mutations() exists as an optimization -- if exhausting mutations is inefficient, one may provide num_mutations()
    to compute the number of mutations more efficiently.

    It's OK if your muations() function yields an indeterminate number of mutations -- it will just mess up the stats
    while the fuzzer is running.
    """

    def __init__(self):
        self._request = None
        self._context_path = None

    def mutations(self, default_value):
        """Generator to yield mutation values for this element.

        Values are either plain values or callable functions that take a "default value" and mutate it. Functions are
        used when the default or "normal" value influences the fuzzed value. Functions are used because the "normal"
        value is sometimes dynamic and not known at the time of generation.

        Each mutation should be a pre-rendered value. That is, it must be suitable to pass to encode().

        Default: Empty iterator.

        Args:
            default_value:
        """
        return
        yield

    def encode(self, value, mutation_context):
        """Takes a value and encodes/renders/serializes it to a bytes (byte string).

        Optional if mutations() yields bytes.

        Example: Yield strings with mutations() and encode them to UTF-8 using encode().

        Default behavior: Return value.

        Args:
            value: Value to encode. Type should match the type yielded by mutations()
            mutation_context (MutationContext): Context for current mutation, if any.


        Returns:
            bytes: Encoded/serialized value.
        """
        return value

    def num_mutations(self, default_value):
        """Return the total number of mutations for this element.

        Default implementation exhausts the mutations() generator, which is inefficient. Override if you can provide a
        value more efficiently, or if exhausting the mutations() generator has side effects.

        Args:
            default_value: Use if number of mutations depends on the default value. Provided by FuzzableWrapper.
                Note: It is generally good behavior to have a consistent number of mutations for a given default value
                length.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return sum(1 for _ in self.mutations(default_value=default_value))

    @property
    def context_path(self):
        """Dot-delimited string that describes the path up to this element. Configured after the object is attached
        to a Request."""
        if not hasattr(self, "_context_path"):
            self._context_path = None
        return self._context_path

    @context_path.setter
    def context_path(self, x):
        self._context_path = x

    @property
    def request(self):
        """Reference to the Request to which this object is attached."""
        if not hasattr(self, "_request"):
            self._request = None
        return self._request

    @request.setter
    def request(self, x):
        self._request = x

    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return True

    def __repr__(self):
        return "<%s with context path: %s>" % (self.__class__.__name__, self.context_path)
