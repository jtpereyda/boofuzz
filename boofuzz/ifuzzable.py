import abc


class DocStringInheritor(type):
    """
    A variation on
    http://groups.google.com/group/comp.lang.python/msg/26f7b4fcb4d66c95
    by Paul McGuire
    """
    def __new__(meta, name, bases, clsdict):
        if not('__doc__' in clsdict and clsdict['__doc__']):
            for mro_cls in (mro_cls for base in bases for mro_cls in base.mro()):
                doc=mro_cls.__doc__
                if doc:
                    clsdict['__doc__']=doc
                    break
        for attr, attribute in clsdict.items():
            if not attribute.__doc__:
                for mro_cls in (mro_cls for base in bases for mro_cls in base.mro()
                                if hasattr(mro_cls, attr)):
                    doc=getattr(getattr(mro_cls,attr),'__doc__')
                    if doc:
                        if isinstance(attribute, property):
                            clsdict[attr] = property(attribute.fget, attribute.fset,
                                                     attribute.fdel, doc)
                        else:
                            attribute.__doc__ = doc
                        break
        return type.__new__(meta, name, bases, clsdict)


class IFuzzable(object):
    """Describes a fuzzable message element or message.

    Design Notes:
     - mutate and reset pretty much form an iterator. Future design goal is
       to eliminate them and add a generator function in their place.
    """
    __metaclass__ = DocStringInheritor

    @abc.abstractproperty
    def fuzzable(self):
        """If False, this element should not be mutated in normal fuzzing."""
        return

    @abc.abstractproperty
    def mutant_index(self):
        """Index of current mutation. 0 => normal value. 1 => first mutation.
        """
        return

    @abc.abstractproperty
    def original_value(self):
        """Original, non-mutated value of element."""
        return

    @abc.abstractproperty
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
    def __nonzero__(self):
        """Make sure instances evaluate to True even if __len__ is zero.

        Design Note: Exists in case some wise guy uses `if my_element:` to
        check for null value.

        Returns:
            bool: True
        """
        return
