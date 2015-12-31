from __future__ import absolute_import
import collections
import zlib
import hashlib
import struct
from . import helpers
from . import primitives
from . import sex
from .primitives import BasePrimitive
from .constants import LITTLE_ENDIAN

REQUESTS = {}
CURRENT = None


class Request(object):
    def __init__(self, name):
        """
        Top level container instantiated by s_initialize(). Can hold any block structure or primitive. This can
        essentially be thought of as a super-block, root-block, daddy-block or whatever other alias you prefer.

        @type  name: str
        @param name: Name of this request
        """

        self.name = name
        self.label = name  # node label for graph rendering.
        self.stack = []  # the request stack.
        self.block_stack = []  # list of open blocks, -1 is last open block.
        self.closed_blocks = {}  # dictionary of closed blocks.
        # dictionary of list of sizers / checksums that were unable to complete rendering:
        self.callbacks = collections.defaultdict(list)
        self.names = {}  # dictionary of directly accessible primitives.
        self.rendered = ""  # rendered block structure.
        self.mutant_index = 0  # current mutation index.
        self.mutant = None  # current primitive being mutated.

    def mutate(self):
        mutated = False

        for item in self.stack:
            if item.fuzzable and item.mutate():
                mutated = True
                if not isinstance(item, Block):
                    self.mutant = item
                break

        if mutated:
            self.mutant_index += 1

        return mutated

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

        # render every item in the stack.
        for item in self.stack:
            item.render()

        # process remaining callbacks.
        for key in self.callbacks.keys():
            for item in self.callbacks[key]:
                item.render()

        # noinspection PyUnusedLocal
        def update_size(stack, name):
            # walk recursively through each block to update its size
            blocks = []

            for stack_item in stack:
                if isinstance(stack_item, Size):
                    stack_item.render()
                elif isinstance(stack_item, Block):
                    blocks += [stack_item]

            for b in blocks:
                update_size(b.stack, b.name)
                b.render()

        # call update_size on each block of the request
        for item in self.stack:
            if isinstance(item, Block):
                update_size(item.stack, item.name)
                item.render()

        # now collect, merge and return the rendered items.
        self.rendered = ""

        for item in self.stack:
            self.rendered += item.rendered

        return self.rendered

    def reset(self):
        """
        Reset every block and primitives mutant state under this request.
        """

        self.mutant_index = 1
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


class Block(object):
    def __init__(self, name, request, group=None, encoder=None, dep=None, dep_value=None, dep_values=None,
                 dep_compare="=="):
        """
        The basic building block. Can contain primitives, sizers, checksums or other blocks.

        @type  name:        str
        @param name:        Name of the new block
        @type  request:     s_request
        @param request:     Request this block belongs to
        @type  group:       str
        @param group:       (Optional, def=None) Name of group to associate this block with
        @type  encoder:     Function Pointer
        @param encoder:     (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
        @type  dep:         str
        @param dep:         (Optional, def=None) Optional primitive whose specific value this block is dependant on
        @type  dep_value:   Mixed
        @param dep_value:   (Optional, def=None) Value that field "dep" must contain for block to be rendered
        @type  dep_values:  List of Mixed Types
        @param dep_values:  (Optional, def=[]) Values that field "dep" may contain for block to be rendered
        @type  dep_compare: str
        @param dep_compare: (Optional, def="==") Comparison method to apply to dependency (==, !=, >, >=, <, <=)
        """

        self.name = name
        self.request = request
        self.group = group
        self.encoder = encoder
        self.dep = dep
        self.dep_value = dep_value
        self.dep_values = dep_values
        self.dep_compare = dep_compare

        self.stack = []  # block item stack.
        self.rendered = ""  # rendered block contents.
        self.fuzzable = True  # blocks are always fuzzable because they may contain fuzzable items.
        self.group_idx = 0  # if this block is tied to a group, the index within that group.
        self.fuzz_complete = False  # whether or not we are done fuzzing this block.
        self.mutant_index = 0  # current mutation index.

    def mutate(self):
        mutated = False

        # are we done with this block?
        if self.fuzz_complete:
            return False

        #
        # mutate every item on the stack for every possible group value.
        #
        if self.group:
            group_count = self.request.names[self.group].num_mutations()

            # update the group value to that at the current index.
            self.request.names[self.group].value = self.request.names[self.group].values[self.group_idx]

            # mutate every item on the stack at the current group value.
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item
                    break

            # if the possible mutations for the stack are exhausted.
            if not mutated:
                # increment the group value index.
                self.group_idx += 1

                # if the group values are exhausted, we are done with this block.
                if self.group_idx == group_count:
                    # restore the original group value.
                    self.request.names[self.group].value = self.request.names[self.group].original_value

                # otherwise continue mutating this group/block.
                else:
                    # update the group value to that at the current index.
                    self.request.names[self.group].value = self.request.names[self.group].values[self.group_idx]

                    # this the mutate state for every item in this blocks stack.
                    # NOT THE BLOCK ITSELF THOUGH! (hence why we didn't call self.reset())
                    for item in self.stack:
                        if item.fuzzable:
                            item.reset()

                    # now mutate the first field in this block before continuing.
                    # (we repeat a test case if we don't mutate something)
                    for item in self.stack:
                        if item.fuzzable and item.mutate():
                            mutated = True

                            if not isinstance(item, Block):
                                self.request.mutant = item

                            break
        #
        # no grouping, mutate every item on the stack once.
        #
        else:
            for item in self.stack:
                if item.fuzzable and item.mutate():
                    mutated = True

                    if not isinstance(item, Block):
                        self.request.mutant = item

                    break

        # if this block is dependant on another field, then manually update that fields value appropriately while we
        # mutate this block. we'll restore the original value of the field prior to continuing.
        if mutated and self.dep:
            # if a list of values was specified, use the first item in the list.
            if self.dep_values:
                self.request.names[self.dep].value = self.dep_values[0]

            # if a list of values was not specified, assume a single value is present.
            else:
                self.request.names[self.dep].value = self.dep_value

        # we are done mutating this block.
        if not mutated:
            self.fuzz_complete = True

            # if we had a dependency, make sure we restore the original value.
            if self.dep:
                self.request.names[self.dep].value = self.request.names[self.dep].original_value

        return mutated

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

        # if this block is associated with a group, then multiply out the number of possible mutations.
        if self.group:
            num_mutations *= len(self.request.names[self.group].values)

        return num_mutations

    def push(self, item):
        """
        Push an arbitrary item onto this blocks stack.
        @type item: BasePrimitive | Block | Size | Repeat
        @param item: Some primitive/block/etc.
        """

        self.stack.append(item)

    def render(self):
        """
        Step through every item on this blocks stack and render it. Subsequent blocks recursively render their stacks.
        """

        #
        # if this block is dependant on another field and the value is not met, render nothing.
        #

        if self.dep:
            if self.dep_compare == "==":
                if self.dep_values and self.request.names[self.dep].value not in self.dep_values:
                    self.rendered = ""
                    return

                elif not self.dep_values and self.request.names[self.dep].value != self.dep_value:
                    self.rendered = ""
                    return

            if self.dep_compare == "!=":
                if self.dep_values and self.request.names[self.dep].value in self.dep_values:
                    self.rendered = ""
                    return

                elif self.request.names[self.dep].value == self.dep_value:
                    self.rendered = ""
                    return

            if self.dep_compare == ">" and self.dep_value <= self.request.names[self.dep].value:
                self.rendered = ""
                return

            if self.dep_compare == ">=" and self.dep_value < self.request.names[self.dep].value:
                self.rendered = ""
                return

            if self.dep_compare == "<" and self.dep_value >= self.request.names[self.dep].value:
                self.rendered = ""
                return

            if self.dep_compare == "<=" and self.dep_value > self.request.names[self.dep].value:
                self.rendered = ""
                return

        #
        # otherwise, render and encode as usual.
        #

        # recursively render the items on the stack.
        for item in self.stack:
            item.render()

        # now collect and merge the rendered items.
        self.rendered = ""

        for item in self.stack:
            self.rendered += item.rendered

        # add the completed block to the request dictionary.
        self.request.closed_blocks[self.name] = self

        # if an encoder was attached to this block, call it.
        if self.encoder:
            self.rendered = self.encoder(self.rendered)

        # the block is now closed, clear out all the entries from the request back splice dictionary.
        if self.name in self.request.callbacks:
            for item in self.request.callbacks[self.name]:
                item.render()

        # now collect and merge the rendered items (again).
        self.rendered = ""

        for item in self.stack:
            self.rendered += item.rendered

    def reset(self):
        """
        Reset the primitives on this blocks stack to the starting mutation state.
        """

        self.fuzz_complete = False
        self.group_idx = 0

        for item in self.stack:
            if item.fuzzable:
                item.reset()

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


class Checksum(primitives.BasePrimitive):
    checksum_lengths = {
        "crc32": 4,
        "adler32": 4,
        "md5": 16,
        "sha1": 20,
        "ipv4": 2,
        "udp": 2
    }

    def __init__(self, block_name, request, algorithm="crc32", length=0, endian=LITTLE_ENDIAN, fuzzable=True,
                 name=None,
                 ipv4_src_block_name=None,
                 ipv4_dst_block_name=None):
        """
        Create a checksum block bound to the block with the specified name. You *can not* create a checksum for any
        currently open blocks.

        @type  block_name: str
        @param block_name: Name of block to apply sizer to

        @type  request:    s_request
        @param request:    Request this block belongs to

        @type  algorithm:  str or def
        @param algorithm:  (Optional, def=crc32) Checksum algorithm to use. (crc32, adler32, md5, sha1, ipv4, udp)

        @type  length:     int
        @param length:     (Optional, def=0) Length of checksum, specify 0 to auto-calculate.
                           Must be specified manually when using custom algorithm.
        @type  endian:     Character
        @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)

        @type  fuzzable:   bool
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing.

        @type  name:       str
        @param name:       Name of this checksum field

        @type ipv4_src_block_name: str
        @param ipv4_src_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 source address.

        @type ipv4_dst_block_name: str
        @param ipv4_dst_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 destination address.
        """
        super(Checksum, self).__init__()
        self.s_type = "checksum"

        self.block_name = block_name
        self.request = request
        self.algorithm = algorithm
        self.length = length
        self.endian = endian
        self.name = name
        self._ipv4_src_block_name = ipv4_src_block_name
        self._ipv4_dst_block_name = ipv4_dst_block_name

        self.fuzzable = fuzzable

        if not self.length and self.algorithm in self.checksum_lengths.iterkeys():
            self.length = self.checksum_lengths[self.algorithm]

        # Edge cases and a couple arbitrary strings (all 1s, all Es)
        self.fuzz_library = ['\x00' * self.length,
                             '\x11' * self.length,
                             '\xEE' * self.length,
                             '\xFF' * self.length,
                             '\xFF' * (self.length - 1) + '\xFE',
                             '\x00' * (self.length - 1) + '\x01']

        if self.algorithm == 'udp':
            if not self._ipv4_src_block_name:
                raise sex.SullyRuntimeError("'udp' checksum algorithm requires ipv4_src_block_name")
            if not self._ipv4_dst_block_name:
                raise sex.SullyRuntimeError("'udp' checksum algorithm requires ipv4_dst_block_name")

        self.rendered = self._get_dummy_value()

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def _checksum(self):
        """
        Calculate and return the checksum (in raw bytes).

        Precondition: _render_dependencies() was just called.

        @rtype:  str
        @return: Checksum.
        """
        data = self.request.names[self.block_name].rendered
        if type(self.algorithm) is str:
            if self.algorithm == "crc32":
                check = struct.pack(self.endian + "L", (zlib.crc32(data) & 0xFFFFFFFFL))

            elif self.algorithm == "adler32":
                check = struct.pack(self.endian + "L", (zlib.adler32(data) & 0xFFFFFFFFL))

            elif self.algorithm == "ipv4":
                check = struct.pack(self.endian + "H", helpers.ipv4_checksum(data))

            elif self.algorithm == "udp":
                return struct.pack(self.endian + "H",
                                   helpers.udp_checksum(msg=data,
                                                        src_addr=self.request.names[self._ipv4_src_block_name].rendered,
                                                        dst_addr=self.request.names[self._ipv4_dst_block_name].rendered,
                                                        )
                                   )

            elif self.algorithm == "md5":
                digest = hashlib.md5(data).digest()

                # TODO: is this right?
                if self.endian == ">":
                    (a, b, c, d) = struct.unpack("<LLLL", digest)
                    digest = struct.pack(">LLLL", a, b, c, d)

                check = digest

            elif self.algorithm == "sha1":
                digest = hashlib.sha1(data).digest()

                # TODO: is this right?
                if self.endian == ">":
                    (a, b, c, d, e) = struct.unpack("<LLLLL", digest)
                    digest = struct.pack(">LLLLL", a, b, c, d, e)

                check = digest

            else:
                raise sex.SullyRuntimeError("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self.algorithm)
        else:
            check = self.algorithm(data)

        if self.length:
            return check[:self.length]
        else:
            return check

    def _get_dummy_value(self):
        return self.checksum_lengths[self.algorithm] * '\x00'

    def _render_dependencies(self):
        """
        Renders all dependencies.
        Precondition: _dependencies_check_and_set() returns True.

        :return None
        """
        # Algorithm for each dependency:
        # 1. Set the recursion flag (avoids recursion loop in step b if target
        #    block contains self).
        # 2. Render the target block.
        # 3. Clear recursion flag.

        if self.block_name:
            self._recursion_flag = True
            self.request.names[self.block_name].render()
            self._recursion_flag = False
        elif self._ipv4_src_block_name:
            self._recursion_flag = True
            self.request.names[self._ipv4_src_block_name].render()
            self._recursion_flag = False
        elif self._ipv4_dst_block_name:
            self._recursion_flag = True
            self.request.names[self._ipv4_dst_block_name].render()
            self._recursion_flag = False

    def render(self):
        """
        Calculate the checksum of the specified block using the specified algorithm.
        """
        # Algorithm summary:
        # 1. If fuzzable, use fuzz library.
        # 2. Else-if the recursion flag is set, just render a dummy value.
        # 3. Else (if the recursion flag is not set), calculate checksum:
        #     a. Render dependencies.
        #     b. Calculate checksum.

        if self.fuzzable and self.mutant_index and not self.fuzz_complete:
            self.rendered = self.value
        elif self._recursion_flag:
            self.rendered = self._get_dummy_value()
        else:
            self._render_dependencies()
            self.rendered = self._checksum()

        return self.rendered

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        return self.length

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True


class Repeat:
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(self, block_name, request, min_reps=0, max_reps=None, step=1, variable=None, fuzzable=True, name=None):
        """
        Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
        default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
        modifier MUST come after the block it is being applied to.

        @type  block_name: str
        @param block_name: Name of block to apply sizer to
        @type  request:    s_request
        @param request:    Request this block belongs to
        @type  min_reps:   int
        @param min_reps:   (Optional, def=0) Minimum number of block repetitions
        @type  max_reps:   int
        @param max_reps:   (Optional, def=None) Maximum number of block repetitions
        @type  step:       int
        @param step:       (Optional, def=1) Step count between min and max reps
        @type  variable:   Sulley Integer Primitive
        @param variable:   (Optional, def=None) Repetitions will be derived from this variable, disables fuzzing
        @type  fuzzable:   bool
        @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
        @type  name:       str
        @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
        """

        self.block_name = block_name
        self.request = request
        self.variable = variable
        self.min_reps = min_reps
        self.max_reps = max_reps
        self.step = step
        self.fuzzable = fuzzable
        self.name = name

        self.value = ""
        self.original_value = ""  # default to nothing!
        self.rendered = ""  # rendered value
        self.fuzz_complete = False  # flag if this primitive has been completely fuzzed
        self.fuzz_library = []  # library of static fuzz heuristics to cycle through.
        self.mutant_index = 0  # current mutation number
        self.current_reps = min_reps  # current number of repetitions

        # ensure the target block exists.
        if self.block_name not in self.request.names:
            raise sex.SullyRuntimeError(
                "Can't add repeater for non-existent block: %s!" % self.block_name
            )

        # ensure the user specified either a variable to tie this repeater to or a min/max val.
        if self.variable is None and self.max_reps is None:
            raise sex.SullyRuntimeError(
                "Repeater for block %s doesn't have a min/max or variable binding!" % self.block_name
            )

        # if a variable is specified, ensure it is an integer type.
        if self.variable and not isinstance(self.variable, primitives.BitField):
            print self.variable
            raise sex.SullyRuntimeError(
                "Attempt to bind the repeater for block %s to a non-integer primitive!" % self.block_name
            )

        # if not binding variable was specified, propagate the fuzz library with the repetition counts.
        if not self.variable:
            self.fuzz_library = range(self.min_reps, self.max_reps + 1, self.step)
        # otherwise, disable fuzzing as the repetition count is determined by the variable.
        else:
            self.fuzzable = False

    def mutate(self):
        """
        Mutate the primitive by stepping through the fuzz library, return False on completion. If variable-bounding is
        specified then fuzzing is implicitly disabled. Instead, the render() routine will properly calculate the
        correct repetition and return the appropriate data.

        @rtype:  bool
        @return: True on success, False otherwise.
        """

        # render the contents of the block we are repeating.
        self.request.names[self.block_name].render()

        # if the target block for this sizer is not closed, raise an exception.
        if self.block_name not in self.request.closed_blocks:
            raise sex.SullyRuntimeError(
                "Can't apply repeater to unclosed block: %s" % self.block_name
            )

        # if we've run out of mutations, raise the completion flag.
        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        # if fuzzing was disabled or complete, and mutate() is called, ensure the original value is restored.
        if not self.fuzzable or self.fuzz_complete:
            self.value = self.original_value
            self.current_reps = self.min_reps
            return False

        if self.variable:
            self.current_reps = self.variable.value
        else:
            self.current_reps = self.fuzz_library[self.mutant_index]

        # set the current value as a multiple of the rendered block based on the current fuzz library count.
        block = self.request.closed_blocks[self.block_name]
        self.value = block.rendered * self.fuzz_library[self.mutant_index]

        # increment the mutation count.
        self.mutant_index += 1

        return True

    def num_mutations(self):
        """
        Determine the number of repetitions we will be making.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        return len(self.fuzz_library)

    def render(self):
        """
        Nothing fancy on render, simply return the value.
        """

        # if the target block for this sizer is not closed, raise an exception.
        if self.block_name not in self.request.closed_blocks:
            raise sex.SullyRuntimeError("CAN NOT APPLY REPEATER TO UNCLOSED BLOCK: %s" % self.block_name)

        # if a variable-bounding was specified then set the value appropriately.
        if self.variable:
            block = self.request.closed_blocks[self.block_name]
            self.value = block.rendered * self.variable.value

        self.rendered = self.value
        return self.rendered

    def reset(self):
        """
        Reset the fuzz state of this primitive.
        """
        self.fuzz_complete = False
        self.mutant_index = 0
        self.value = self.original_value

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        return self.current_reps * len(self.request.names[self.block_name])

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True


class Size:
    """
    This block type is kind of special in that it is a hybrid between a block and a primitive (it can be fuzzed). The
    user does not need to be wary of this fact.
    """

    def __init__(self, block_name, request, offset=0, length=4, endian="<", output_format="binary", inclusive=False,
                 signed=False, math=None, fuzzable=False, name=None):
        """
        Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
        currently open blocks.

        @type  block_name:    str
        @param block_name:    Name of block to apply sizer to
        @type  request:       s_request
        @param request:       Request this block belongs to
        @type  length:        int
        @param length:        (Optional, def=4) Length of sizer
        @type  offset:        int
        @param offset:        (Optional, def=0) Offset for calculated size value
        @type  endian:        chr
        @param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
        @type  output_format: str
        @param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
        @type  inclusive:     bool
        @param inclusive:     (Optional, def=False) Should the sizer count its own length?
        @type  signed:        bool
        @param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
        @type  math:          def
        @param math:          (Optional, def=None) Apply the mathematical op defined in this function to the size
        @type  fuzzable:      bool
        @param fuzzable:      (Optional, def=False) Enable/disable fuzzing of this sizer
        @type  name:          str
        @param name:          Name of this sizer field
        """

        self.block_name = block_name
        self.request = request
        self.offset = offset
        self.length = length
        self.endian = endian
        self.format = output_format
        self.inclusive = inclusive
        self.signed = signed
        self.math = math
        self.fuzzable = fuzzable
        self.name = name

        self.original_value = "N/A"  # for get_primitive
        self.s_type = "size"  # for ease of object identification
        self.bit_field = primitives.BitField(
            0,
            self.length * 8,
            endian=self.endian,
            output_format=self.format,
            signed=self.signed
        )
        self.rendered = ""
        self.fuzz_complete = self.bit_field.fuzz_complete
        self.fuzz_library = self.bit_field.fuzz_library
        self.mutant_index = self.bit_field.mutant_index
        self.value = self.bit_field.value

        if not self.math:
            self.math = lambda (x): x

    def exhaust(self):
        """
        Exhaust the possible mutations for this primitive.

        @rtype:  int
        @return: The number of mutations to reach exhaustion
        """

        num = self.num_mutations() - self.mutant_index

        self.fuzz_complete = True
        self.mutant_index = self.num_mutations()
        self.bit_field.mutant_index = self.num_mutations()
        self.value = self.original_value

        return num

    def mutate(self):
        """
        Wrap the mutation routine of the internal bit_field primitive.

        @rtype:  Boolean
        @return: True on success, False otherwise.
        """

        if self.mutant_index == self.num_mutations():
            self.fuzz_complete = True

        self.mutant_index += 1

        return self.bit_field.mutate()

    def num_mutations(self):
        """
        Wrap the num_mutations routine of the internal bit_field primitive.

        @rtype:  int
        @return: Number of mutated forms this primitive can take.
        """

        return self.bit_field.num_mutations()

    def render(self):
        """
        Render the sizer.

        :return Rendered value.
        """
        # if the sizer is fuzzable and we have not yet exhausted the the possible bit field values, use the fuzz value.
        if self.fuzzable and self.bit_field.mutant_index and not self.bit_field.fuzz_complete:
            self.rendered = self.bit_field.render()
        else:
            length = self.offset
            if self.inclusive:
                length += self.length
            length += len(self.request.names[self.block_name])

            self.bit_field.value = self.math(length)

            self.rendered = self.bit_field.render()

        return self.rendered

    def reset(self):
        """
        Wrap the reset routine of the internal bit_field primitive.
        """

        self.bit_field.reset()

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    def __len__(self):
        return self.length

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
