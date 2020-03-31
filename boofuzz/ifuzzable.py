import abc

from builtins import object
from future.utils import listitems, with_metaclass


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
class IFuzzable(with_metaclass(DocStringInheritor, object)):
    """Describes a fuzzable message element or message.

    The core functionality on which boofuzz runs:

    1. mutations() -- iterate mutations.
    2. mutant_index, mutate(), render(), reset() are an older interface used to simulate mutations().
    3. render() returns either the normal value or the currently-being-mutated value.
    3. name() -- gets the specific element's name; may be replaced in the future.
    4. fuzzable() -- indicates whether an element should be fuzzed. This used to be checked externally, but is now
                     checked within mutations()
    5. original_value() -- used to get the default value of the element.
    6. num_mutations() -- Number of mutations that an element yields.
    7. __len__() -- an element should describe its own size when rendered.
    8. __repr__() -- for nice readable user interfaces
    9. __nonzero__() -- Allows one to use `if someFuzzableObject` to check for null. Questionable practice.

    The mutation and original_value functions are the most fundamental.

    """

    def mutations(self):
        """Yields mutations.

        Each mutation should be a pre-rendered value. That is, it must be suitable to pass to encode().
        """
        return
        yield

    def num_mutations(self):
        """Return the total number of mutations for this element.

        Default implementation exhausts the mutations() generator, which is inefficient. Override if you can provide a
        value more efficiently, or if exhausting the mutations() generator has side effects.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return sum(1 for _ in self.mutations())

    def encode(self, value, child_data, mutation):
        """Takes a fuzz value and encodes/renders/serializes that value.

        The value may be a default value, or may be a value yielded by mutations().

        By default, simply returns value.

        Returns:
            bytes: Encoded/serialized value.
        """
        return value

    def get_child_data(self, mutation):
        """Return child data for this node. Only applies to complex mutators."""
        return None

    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return True
