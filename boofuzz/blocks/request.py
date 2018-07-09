import collections

from .. import sex
from .block import Block
from ..ifuzzable import IFuzzable


class Request(IFuzzable):
    def __init__(self, name):
        """
        Top level container instantiated by s_initialize(). Can hold any block structure or primitive. This can
        essentially be thought of as a super-block, root-block, daddy-block or whatever other alias you prefer.

        @type  name: str
        @param name: Name of this request
        """

        self._name = name
        self.label = name  # node label for graph rendering.
        self.stack = []  # the request stack.
        self.block_stack = []  # list of open blocks, -1 is last open block.
        self.closed_blocks = {}  # dictionary of closed blocks.
        # dictionary of list of sizers / checksums that were unable to complete rendering:
        self.callbacks = collections.defaultdict(list)
        self.names = {}  # dictionary of directly accessible primitives.
        self._rendered = ""  # rendered block structure.
        self._mutant_index = 0  # current mutation index.
        self._element_mutant_index = None  # index of current mutant element within self.stack
        self.mutant = None  # current primitive being mutated.

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def mutant_index(self):
        return self._mutant_index

    @mutant_index.setter
    def mutant_index(self, value):
        if isinstance(value, int):
            self._mutant_index = value
        else:
            raise TypeError('Expected an Int')

    @property
    def fuzzable(self):
        return True

    @property
    def original_value(self):
        # ensure there are no open blocks lingering.
        if self.block_stack:
            raise sex.SullyRuntimeError("UNCLOSED BLOCK: %s" % self.block_stack[-1].name)

        self._rendered = ""

        for item in self.stack:
            self._rendered += item.original_value

        return self._rendered

    def mutate(self):
        if self._element_mutant_index is None:
            self._element_mutant_index = 0

        mutated = False

        while self._element_mutant_index < len(self.stack):
            item = self.stack[self._element_mutant_index]
            if item.fuzzable and item.mutate():
                mutated = True
                if not isinstance(item, Block):
                    self.mutant = item
                break
            else:
                self._element_mutant_index += 1

        if mutated:
            self._mutant_index += 1

        return mutated

    def skip_element(self):
        self.stack[self._element_mutant_index].reset()
        self._element_mutant_index += 1

    def num_mutations(self):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """
        num_mutations = 0

        for item in self.stack:
            if item.fuzzable:
                num_mutations += item.num_mutations()

        return num_mutations

    def pop(self):
        """
        The last open block was closed, so pop it off of the block stack.
        """

        if not self.block_stack:
            raise sex.SullyRuntimeError("BLOCK STACK OUT OF SYNC")

        self.block_stack.pop()

    def push(self, item):
        """
        Push an item into the block structure. If no block is open, the item goes onto the request stack. otherwise,
        the item goes onto the last open blocks stack.

        @type item: BasePrimitive | Block | Request | Size | Repeat
        @param item: Some primitive/block/request/etc.
        """
        # if the item has a name, add it to the internal dictionary of names.
        if hasattr(item, "name") and item.name:
            # ensure the name doesn't already exist.
            if item.name in self.names.keys():
                raise sex.SullyRuntimeError("BLOCK NAME ALREADY EXISTS: %s" % item.name)

            self.names[item.name] = item

        # if there are no open blocks, the item gets pushed onto the request stack.
        # otherwise, the pushed item goes onto the stack of the last opened block.
        if not self.block_stack:
            self.stack.append(item)
        else:
            self.block_stack[-1].push(item)

        # add the opened block to the block stack.
        if isinstance(item, Block):
            self.block_stack.append(item)

    def render(self):
        # ensure there are no open blocks lingering.
        if self.block_stack:
            raise sex.SullyRuntimeError("UNCLOSED BLOCK: %s" % self.block_stack[-1].name)

        self._rendered = b""

        for item in self.stack:
            self._rendered += item.render()

        return self._rendered

    def reset(self):
        """
        Reset every block and primitives mutant state under this request.
        """

        self._element_mutant_index = None
        self._mutant_index = 1
        self.closed_blocks = {}

        for item in self.stack:
            if item.fuzzable:
                item.reset()

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
            if isinstance(item, Block):
                for stack_item in self.walk(item.stack):
                    yield stack_item
            else:
                yield item

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        length = 0
        for item in self.stack:
            length += len(item)
        return length

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
