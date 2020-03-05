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
    2. mutant_index, render(), reset() are an older interface used to simulate mutations().
    3. render() returns either the normal value or the currently-being-mutated value.
    3. name() -- gets the specific element's name; may be replaced in the future.
    4. fuzzable() -- indicates whether an element should be fuzzed.
    5. original_value() -- used to get the default value of the element.
    6. num_mutations() -- Number of mutations that an element yields.
    7. __len__() -- an element should describe its own size when rendered.
    8. __repr__() -- for nice readable user interfaces
    9. __nonzero__() -- Allows one to use `if someFuzzableObject` to check for null. Questionable practice.

    The mutation and original_value functions are the most fundamental.

    """

    @property
    @abc.abstractmethod
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return

    @abc.abstractproperty
    def mutations(self):
        """Yields mutations."""
        return

    @property
    @abc.abstractmethod
    def mutant_index(self):
        """Index of current mutation. 0 => normal value. 1 => first mutation.
        """
        return

    @property
    @abc.abstractmethod
    def original_value(self):
        """Original, non-mutated value of element."""
        return

    @property
    @abc.abstractmethod
    def name(self):
        """Element name, should be specific for each instance."""
        return

    @abc.abstractmethod
    def mutate(self):
        """Mutate this element. Returns True each time and False on completion.

        Use reset() after completing mutations to bring back to original state.

        Mutated values available through render().

        Returns:
            bool: True if there are mutations left, False otherwise.
        """
        return

    @abc.abstractmethod
    def num_mutations(self):
        """Return the total number of mutations for this element.

        Returns:
            int: Number of mutated forms this primitive can take
        """
        return

    @abc.abstractmethod
    def render(self):
        """Return rendered value. Equal to original value after reset().
        """
        return

    @abc.abstractmethod
    def reset(self):
        """Reset element to pre-mutation state."""
        return

    @abc.abstractmethod
    def __repr__(self):
        return

    @abc.abstractmethod
    def __len__(self):
        """Length of field. May vary if mutate() changes the length.

        Returns:
            int: Length of element (length of mutated element if mutated).
        """
        return

    @abc.abstractmethod
    def __bool__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return
