import collections

from .aligned import Aligned
from .block import Block
from .. import exception
from ..constants import ERR_NAME_NO_RESOLVE, ERR_NAME_NOT_FOUND, ERR_NAME_TOO_MANY
from ..exception import BoofuzzNameResolutionError
from ..fuzzable import Fuzzable
from ..fuzzable_block import FuzzableBlock


class Request(FuzzableBlock):
    """Top level container. Can hold any block structure or primitive.

    This can essentially be thought of as a super-block, root-block, daddy-block or whatever other alias you prefer.

    :param name: Name of this request
    :type name: str, optional
    :param children: Children of this request, defaults to None
    :type children: boofuzz.Fuzzable, optional
    """

    def __init__(self, name=None, children=None):
        super(Request, self).__init__(name=name, request=self)
        self.label = name  # node label for graph rendering.
        self.stack = []  # the request stack.
        self.block_stack = []  # list of open blocks, -1 is last open block.
        self.callbacks = collections.defaultdict(list)
        self.names = {name: self}  # dictionary of directly accessible primitives.
        self._rendered = b""  # rendered block structure.
        self._mutant_index = 0  # current mutation index.
        self._element_mutant_index = None  # index of current mutant element within self.stack
        self.mutant = None  # current primitive being mutated.

        if children is None:
            children = []
        elif isinstance(children, Fuzzable):
            children = [children]

        self._initialize_children(child_nodes=children)

    def _initialize_children(self, child_nodes, block_stack=None):
        if block_stack is None:
            block_stack = list()

        for item in child_nodes:
            item.context_path = self._generate_context_path(block_stack)
            item.request = self
            # ensure the name doesn't already exist.
            if item.qualified_name in list(self.names):
                raise exception.SullyRuntimeError("BLOCK NAME ALREADY EXISTS: %s" % item.qualified_name)
            self.names[item.qualified_name] = item

            if len(block_stack) == 0:
                self.stack.append(item)
            if isinstance(item, Block) or isinstance(item, Aligned):  # TODO generic check here
                block_stack.append(item)
                self._initialize_children(child_nodes=item.stack, block_stack=block_stack)
                block_stack.pop()

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def fuzzable(self):
        return True

    def pop(self):
        """
        The last open block was closed, so pop it off of the block stack.
        """

        if not self.block_stack:
            raise exception.SullyRuntimeError("BLOCK STACK OUT OF SYNC")

        self.block_stack.pop()

    def push(self, item):
        """
        Push an item into the block structure. If no block is open, the item goes onto the request stack. otherwise,
        the item goes onto the last open blocks stack.

        What this method does:
        1. Sets context_path for each pushed FuzzableWrapper.
        2. Sets request for each FuzzableWrapper
        3. Checks for duplicate qualified_name items
        4. Adds item to self.names map (based on qualified_name)
        5. Adds the item to self.stack, or to the stack of the currently opened block.

        Also: Manages block_stack, mostly an implementation detail to help static protocol definition

        @type item: BasePrimitive | Block | Request | Size | Repeat
        @param item: Some primitive/block/request/etc.
        """
        item.context_path = self._generate_context_path(self.block_stack)
        item.request = self
        # ensure the name doesn't already exist.
        if item.qualified_name in list(self.names):
            raise exception.SullyRuntimeError("BLOCK NAME ALREADY EXISTS: %s" % item.qualified_name)

        self.names[item.qualified_name] = item

        # if there are no open blocks, the item gets pushed onto the request stack.
        # otherwise, the pushed item goes onto the stack of the last opened block.
        if not self.block_stack:
            self.stack.append(item)
        else:
            self.block_stack[-1].push(item)

        # add the opened block to the block stack.
        if isinstance(item, Block) or isinstance(item, Aligned):  # TODO generic check here
            self.block_stack.append(item)

    def _generate_context_path(self, block_stack):
        context_path = ".".join(x.name for x in block_stack)  # TODO put in method
        context_path = ".".join(filter(None, (self.name, context_path)))
        return context_path

    def render(self, mutation_context=None):
        if self.block_stack:
            raise exception.SullyRuntimeError("UNCLOSED BLOCK: %s" % self.block_stack[-1].qualified_name)

        return self.get_child_data(mutation_context=mutation_context)

    def walk(self, stack=None):
        """
        Recursively walk through and yield every primitive and block on the request stack.

        @param stack: Set to none -- used internally by recursive calls.
                      If None, uses self.stack.

        @rtype:  Sulley Primitives
        @return: Sulley Primitives
        """

        if not stack:
            stack = self.stack

        for item in stack:
            # if the item is a block, step into it and continue looping.
            if isinstance(item, Block) or isinstance(item, Aligned):  # TODO generic check here
                for stack_item in self.walk(item.stack):
                    yield stack_item
            else:
                yield item

    def resolve_name(self, context_path, name):
        """
        Names are resolved thus:
        1. If the name starts with a dot, it is treated as a relative path name in the style of PEP 328.
            1. "." refers to the current directory, so to speak.
            2. ".." refers to the next directory up.
            3. "..." refers to another directory up, and so forth.
        2. If the name does _not_ start with a dot, it is treated as an absolute name.
        3. Backwards compatibility: If the absolute name fails to resolve, the engine searches for any block or
            primitive with that name. If more or less than exactly one match is found, an error results.

        Args:
            context_path: The "current working directory" for resolving the name. E.g. "block_1.block_2".
            name: The name being resolved. May be absolute or relative.

        Returns:

        """
        if name is None:
            raise BoofuzzNameResolutionError(ERR_NAME_NOT_FOUND.format(name))
        if name.startswith("."):  # Case 1 relative
            components = (context_path + name).split(".")  # double dots leave an empty string; so do trailing dots
            while "" in components:
                i = components.index("")
                if i <= 0:
                    raise BoofuzzNameResolutionError(ERR_NAME_NO_RESOLVE.format(name, context_path))
                elif i == len(components) - 1:  # last in list; indicates a trailing dot
                    del components[i]
                else:  # double dot
                    del components[i]
                    del components[i - 1]
            return self._lookup_resolved_name(".".join(components))
        else:
            full_absolute_name = "{0}.{1}".format(self._name, name)
            if full_absolute_name in self.names:  # Case 2 absolute
                return self._lookup_resolved_name(full_absolute_name)
            else:  # Case 3 backwards compatibility --  look up by last name component
                found_names = [n for n in self.names if n.rsplit(".")[-1] == name]
                if len(found_names) == 1:
                    return self.names[found_names[0]]
                elif len(found_names) == 0:
                    raise BoofuzzNameResolutionError(ERR_NAME_NOT_FOUND.format(name))
                else:
                    raise BoofuzzNameResolutionError(ERR_NAME_TOO_MANY.format(name, found_names))

    def _lookup_resolved_name(self, resolved_name):
        if resolved_name in self.names:
            return self.names[resolved_name]
        else:
            raise BoofuzzNameResolutionError(ERR_NAME_NOT_FOUND.format(resolved_name))

    def get_mutations(self, default_value=None):
        return self.mutations(default_value=default_value)

    def get_num_mutations(self):
        return self.num_mutations()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)
