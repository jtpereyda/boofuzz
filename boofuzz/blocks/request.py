import collections

from .block import Block
from .aligned import Aligned
from .. import exception, helpers
from ..mutator import Mutator
from ..fuzzable_block import FuzzableBlock
from ..mutation_context import MutationContext


class Request(FuzzableBlock):
    def __init__(self, name, child_nodes=None):
        """
        Top level container instantiated by s_initialize(). Can hold any block structure or primitive. This can
        essentially be thought of as a super-block, root-block, daddy-block or whatever other alias you prefer.

        @type  name: str
        @param name: Name of this request
        """

        super().__init__(request=self)
        self._name = name
        self.label = name  # node label for graph rendering.
        self.stack = []  # the request stack.
        self.block_stack = []  # list of open blocks, -1 is last open block.
        self.closed_blocks = {}  # dictionary of closed blocks.
        # dictionary of list of sizers / checksums that were unable to complete rendering:
        self.callbacks = collections.defaultdict(list)
        self.names = {}  # dictionary of directly accessible primitives.
        self._rendered = b""  # rendered block structure.
        self._mutant_index = 0  # current mutation index.
        self._element_mutant_index = None  # index of current mutant element within self.stack
        self.mutant = None  # current primitive being mutated.

        if child_nodes is None:
            child_nodes = []
        self._initialize_children(child_nodes=child_nodes)

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
            if (
                isinstance(item, Block)
                or isinstance(item, Aligned)
                or isinstance(item.fuzz_object, Block)
                or isinstance(item.fuzz_object, Aligned)
            ):  # TODO generic check here
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
            self.block_stack[-1].fuzz_object.push(item)

        # add the opened block to the block stack.
        if (
            isinstance(item, Block)
            or isinstance(item, Aligned)
            or isinstance(item.fuzz_object, Block)
            or isinstance(item.fuzz_object, Aligned)
        ):  # TODO generic check here
            self.block_stack.append(item)

    def _generate_context_path(self, block_stack):
        context_path = ".".join(x.name for x in block_stack)  # TODO put in method
        context_path = ".".join(filter(None, (self.name, context_path)))
        return context_path

    def render(self, mutation_context):
        if self.block_stack:
            raise exception.SullyRuntimeError("UNCLOSED BLOCK: %s" % self.block_stack[-1].qualified_name)

        return super(Request, self).get_child_data(mutation_context=mutation_context)

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
            if (
                isinstance(item, Block)
                or isinstance(item, Aligned)
                or isinstance(item.fuzz_object, Block)
                or isinstance(item.fuzz_object, Aligned)
            ):  # TODO generic check here
                for stack_item in self.walk(item.stack):
                    yield stack_item
            else:
                yield item

    def resolve_name(self, context_path, name):
        context_components = context_path.split(".")
        name_components = name.split(".")

        if name_components[0] == "_parent":  # if path is relative
            del name_components[0]
            components = context_components + name_components
            i = 0
            while i + 1 < len(components):
                if components[i + 1] == "_parent":
                    del components[i + 1]
                    del components[i]
                else:
                    i += 1
        else:
            components = context_components + name_components

        normalized_name = ".".join(components)

        if normalized_name in self.names:
            return self.names[normalized_name]
        elif "." not in name:
            # attempt to look up by last name component
            found_names = []
            for n in self.names:
                if name == n.rsplit(".", 1)[-1]:
                    found_names.append(n)
            if len(found_names) == 0:
                raise "Unable to resolve block name '{0}'".format(name)
            elif len(found_names) == 1:
                return self.names[found_names[0]]
            else:
                raise "Unable to resolve block name '{0}'. Use an absolute or relative name instead. Too many potential matches: {1}".format(
                    name, found_names
                )
        else:
            raise Exception("Failed to resolve block name '{0}' in context '{1}'".format(name, context_path))

    def get_mutations(self, default_value=None):
        return self.mutations(default_value=default_value)

    def get_num_mutations(self):
        return self.num_mutations()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)
