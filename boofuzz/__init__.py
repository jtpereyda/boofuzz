from __future__ import absolute_import
import functools

from . import blocks
from . import legos
from . import pedrpc
from . import primitives
from . import sex

from .blocks.request import Request
from .blocks.block import Block
from .blocks.checksum import Checksum
from .blocks.repeat import Repeat
from .blocks.size import Size
from .constants import BIG_ENDIAN, LITTLE_ENDIAN
from .event_hook import EventHook
from .fuzz_logger import FuzzLogger
from .fuzz_logger_text import FuzzLoggerText
from .fuzz_logger_csv import FuzzLoggerCsv
from .ifuzz_logger import IFuzzLogger
from .ifuzz_logger_backend import IFuzzLoggerBackend
from .itarget_connection import ITargetConnection
from .primitives import (BasePrimitive, Delim, Group,
                         RandomData, Static, String, BitField,
                         Byte, Word, DWord, QWord, FromFile)
from .serial_connection import SerialConnection
from .sessions import Session, Target, open_test_run
from .sex import SullyRuntimeError, SizerNotUtilizedError, MustImplementException
from .socket_connection import SocketConnection

__version__ = '0.0.13'

DEFAULT_PROCMON_PORT = 26002


# REQUEST MANAGEMENT
def s_get(name=None):
    """
    Return the request with the specified name or the current request if name is not specified. Use this to switch from
    global function style request manipulation to direct object manipulation. Example::

        req = s_get("HTTP BASIC")
        print req.num_mutations()

    The selected request is also set as the default current. (ie: s_switch(name) is implied).

    :type  name: str
    :param name: (Optional, def=None) Name of request to return or current request if name is None.

    :rtype:  blocks.request
    :return: The requested request.
    """

    if not name:
        return blocks.CURRENT

    # ensure this gotten request is the new current.
    s_switch(name)

    if name not in blocks.REQUESTS:
        raise sex.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    return blocks.REQUESTS[name]


def s_initialize(name):
    """
    Initialize a new block request. All blocks / primitives generated after this call apply to the named request.
    Use s_switch() to jump between factories.

    :type  name: str
    :param name: Name of request
    """
    if name in blocks.REQUESTS:
        raise sex.SullyRuntimeError("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    blocks.REQUESTS[name] = Request(name)
    blocks.CURRENT = blocks.REQUESTS[name]


def s_mutate():
    """
    Mutate the current request and return False if mutations are exhausted, in which case the request has been reverted
    back to its normal form.

    :rtype:  bool
    :return: True on mutation success, False if mutations exhausted.
    """
    return blocks.CURRENT.mutate()


def s_num_mutations():
    """
    Determine the number of repetitions we will be making.

    :rtype:  int
    :return: Number of mutated forms this primitive can take.
    """

    return blocks.CURRENT.num_mutations()


def s_render():
    """
    Render out and return the entire contents of the current request.

    :rtype:  Raw
    :return: Rendered contents
    """

    return blocks.CURRENT.render()


def s_switch(name):
    """
    Change the current request to the one specified by "name".

    :type  name: str
    :param name: Name of request
    """

    if name not in blocks.REQUESTS:
        raise sex.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    blocks.CURRENT = blocks.REQUESTS[name]


# ## BLOCK MANAGEMENT


def s_block(name, group=None, encoder=None, dep=None, dep_value=None, dep_values=(), dep_compare="=="):
    """
    Open a new block under the current request. The returned instance supports the "with" interface so it will
    be automatically closed for you::

        with s_block("header"):
            s_static("\\x00\\x01")
            if s_block_start("body"):
                ...

    :type  name:        str
    :param name:        Name of block being opened
    :type  group:       str
    :param group:       (Optional, def=None) Name of group to associate this block with
    :type  encoder:     Function Pointer
    :param encoder:     (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
    :type  dep:         str
    :param dep:         (Optional, def=None) Optional primitive whose specific value this block is dependant on
    :type  dep_value:   Mixed
    :param dep_value:   (Optional, def=None) Value that field "dep" must contain for block to be rendered
    :type  dep_values:  List of Mixed Types
    :param dep_values:  (Optional, def=[]) Values that field "dep" may contain for block to be rendered
    :type  dep_compare: str
    :param dep_compare: (Optional, def="==") Comparison method to use on dependency (==, !=, >, >=, <, <=)
    """

    class ScopedBlock(Block):
        def __init__(self, block):
            self.block = block

        def __enter__(self):
            """
            Setup before entering the "with" statement body
            """
            return self.block

        def __exit__(self, type, value, traceback):
            """
            Cleanup after executing the "with" statement body
            """
            # Automagically close the block when exiting the "with" statement
            s_block_end()

    block = s_block_start(name, group, encoder, dep, dep_value, dep_values, dep_compare)

    return ScopedBlock(block)


def s_block_start(name, *args, **kwargs):
    """
    Open a new block under the current request. This routine always returns an instance so you can make your fuzzer pretty
    with indenting::

        if s_block_start("header"):
            s_static("\\x00\\x01")
            if s_block_start("body"):
                ...
        s_block_close()

    :note Prefer using s_block to this function directly
    :see s_block
    """
    block = Block(name, blocks.CURRENT, *args, **kwargs)
    blocks.CURRENT.push(block)

    return block


# noinspection PyUnusedLocal
def s_block_end(name=None):
    """
    Close the last opened block. Optionally specify the name of the block being closed (purely for aesthetic purposes).

    :type  name: str
    :param name: (Optional, def=None) Name of block to closed.
    """
    blocks.CURRENT.pop()


def s_checksum(block_name, algorithm="crc32", length=0, endian=LITTLE_ENDIAN, fuzzable=True, name=None,
               ipv4_src_block_name=None,
               ipv4_dst_block_name=None):
    """
    Create a checksum block bound to the block with the specified name. You *can not* create a checksum for any
    currently open blocks.

    :type  block_name: str
    :param block_name: Name of block to apply sizer to

    :type  algorithm:  str
    :param algorithm:  (Optional, def=crc32) Checksum algorithm to use. (crc32, adler32, md5, sha1, ipv4, udp)

    :type  length:     int
    :param length:     (Optional, def=0) NOT IMPLEMENTED. Length of checksum, specify 0 to auto-calculate

    :type  endian:     Character
    :param endian:     (Optional, def=LITTLE_ENDIAN) Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)

    :type  fuzzable:   bool
    :param fuzzable:   (Optional, def=True) Enable/disable fuzzing.

    :type  name:       str
    :param name:       Name of this checksum field

    :type ipv4_src_block_name: str
    :param ipv4_src_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 source address.

    :type ipv4_dst_block_name: str
    :param ipv4_dst_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 destination address.
    """

    # you can't add a checksum for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.SullyRuntimeError("CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")

    checksum = Checksum(block_name, blocks.CURRENT, algorithm, length, endian, fuzzable, name,
                        ipv4_src_block_name=ipv4_src_block_name,
                        ipv4_dst_block_name=ipv4_dst_block_name)
    blocks.CURRENT.push(checksum)


def s_repeat(block_name, min_reps=0, max_reps=None, step=1, variable=None, fuzzable=True, name=None):
    """
    Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
    default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
    modifier MUST come after the block it is being applied to.

    :see: Aliases: s_repeater()

    :type  block_name: str
    :param block_name: Name of block to apply sizer to
    :type  min_reps:   int
    :param min_reps:   (Optional, def=0) Minimum number of block repetitions
    :type  max_reps:   int
    :param max_reps:   (Optional, def=None) Maximum number of block repetitions
    :type  step:       int
    :param step:       (Optional, def=1) Step count between min and max reps
    :type  variable:   Sulley Integer Primitive
    :param variable:   (Optional, def=None) An integer primitive which will specify the number of repitions
    :type  fuzzable:   bool
    :param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:       str
    :param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    repeat = Repeat(block_name, blocks.CURRENT, min_reps, max_reps, step, variable, fuzzable, name)
    blocks.CURRENT.push(repeat)


def s_size(block_name, offset=0, length=4, endian=LITTLE_ENDIAN, output_format="binary", inclusive=False, signed=False,
           math=None, fuzzable=True, name=None):
    """
    Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
    currently open blocks.

    :see: Aliases: s_sizer()

    :type  block_name:    str
    :param block_name:    Name of block to apply sizer to
    :type  offset:        int
    :param offset:        (Optional, def=0) Offset to calculated size of block
    :type  length:        int
    :param length:        (Optional, def=4) Length of sizer
    :type  endian:        Character
    :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format: str
    :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
    :type  inclusive:     bool
    :param inclusive:     (Optional, def=False) Should the sizer count its own length?
    :type  signed:        bool
    :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  math:          Function
    :param math:          (Optional, def=None) Apply the mathematical operations defined in this function to the size
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this sizer
    :type  name:          str
    :param name:          Name of this sizer field
    """

    # you can't add a size for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise sex.SullyRuntimeError("CAN NOT ADD A SIZE FOR A BLOCK CURRENTLY IN THE STACK")

    size = Size(
        block_name, blocks.CURRENT, offset, length, endian, output_format, inclusive, signed, math, fuzzable, name
    )
    blocks.CURRENT.push(size)


def s_update(name, value):
    """
    Update the value of the named primitive in the currently open request.

    :type  name:  str
    :param name:  Name of object whose value we wish to update
    :type  value: Mixed
    :param value: Updated value
    """

    if name not in map(lambda o: o.name, blocks.CURRENT.walk()):
        raise sex.SullyRuntimeError("NO OBJECT WITH NAME '%s' FOUND IN CURRENT REQUEST" % name)

    blocks.CURRENT.names[name].value = value


# PRIMITIVES


def s_binary(value, name=None):
    """
    Parse a variable format binary string into a static value and push it onto the current block stack.

    :type  value: str
    :param value: Variable format binary string
    :type  name:  str
    :param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    # parse the binary string into.
    parsed = value
    parsed = parsed.replace(" ", "")
    parsed = parsed.replace("\t", "")
    parsed = parsed.replace("\r", "")
    parsed = parsed.replace("\n", "")
    parsed = parsed.replace(",", "")
    parsed = parsed.replace("0x", "")
    parsed = parsed.replace("\\x", "")

    value = ""
    while parsed:
        pair = parsed[:2]
        parsed = parsed[2:]

        value += chr(int(pair, 16))

    static = primitives.Static(value, name)
    blocks.CURRENT.push(static)


def s_delim(value, fuzzable=True, name=None):
    """
    Push a delimiter onto the current block stack.

    :type  value:    Character
    :param value:    Original value
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    delim = primitives.Delim(value, fuzzable, name)
    blocks.CURRENT.push(delim)


def s_group(name, values):
    """
    This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
    to a group primitive to specify that the block should cycle through all possible mutations for *each* value
    within the group. The group primitive is useful for example for representing a list of valid opcodes.

    :type  name:   str
    :param name:   Name of group
    :type  values: List or raw data
    :param values: List of possible raw values this group can take.
    """

    group = primitives.Group(name, values)
    blocks.CURRENT.push(group)


# noinspection PyCallingNonCallable
def s_lego(lego_type, value=None, options=()):
    """
    Legos are pre-built blocks... TODO: finish this doc

    :type  lego_type:   str
    :param lego_type:   Function that represents a lego

    :param value:       Original value

    :param options:     Options to pass to lego.
    """

    # as legos are blocks they must have a name.
    # generate a unique name for this lego.
    name = "LEGO_%08x" % len(blocks.CURRENT.names)

    if lego_type not in legos.BIN:
        raise sex.SullyRuntimeError("INVALID LEGO TYPE SPECIFIED: %s" % lego_type)
    lego = legos.BIN[lego_type](name, blocks.CURRENT, value, options)

    # push the lego onto the stack and immediately pop to close the block.
    blocks.CURRENT.push(lego)
    blocks.CURRENT.pop()


def s_random(value, min_length, max_length, num_mutations=25, fuzzable=True, step=None, name=None):
    """
    Generate a random chunk of data while maintaining a copy of the original. A random length range can be specified.
    For a static length, set min/max length to be the same.

    :type  value:         Raw
    :param value:         Original value
    :type  min_length:    int
    :param min_length:    Minimum length of random block
    :type  max_length:    int
    :param max_length:    Maximum length of random block
    :type  num_mutations: int
    :param num_mutations: (Optional, def=25) Number of mutations to make before reverting to default
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  step:          int
    :param step:          (Optional, def=None) If not null, step count between min and max reps, otherwise random
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    random_data = primitives.RandomData(value, min_length, max_length, num_mutations, fuzzable, step, name)
    blocks.CURRENT.push(random_data)


def s_static(value, name=None):
    """
    Push a static value onto the current block stack.

    :see: Aliases: s_dunno(), s_raw(), s_unknown()

    :type  value: Raw
    :param value: Raw static data
    :type  name:  str
    :param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    static = primitives.Static(value, name)
    blocks.CURRENT.push(static)


def s_string(value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, max_len=0, name=None):
    """
    Push a string onto the current block stack.

    :type  value:    str
    :param value:    Default string value
    :type  size:     int
    :param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
    :type  padding:  Character
    :param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
    :type  encoding: str
    :param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  max_len:  int
    :param max_len:  (Optional, def=0) Maximum string length
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    s = primitives.String(value, size, padding, encoding, fuzzable, max_len, name)
    blocks.CURRENT.push(s)


def s_from_file(value, encoding="ascii", fuzzable=True, max_len=0, name=None, filename=None):
    """
    Push a value from file onto the current block stack.

    :type  value:    str
    :param value:    Default string value
    :type  encoding: str
    :param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  max_len:  int
    :param max_len:  (Optional, def=0) Maximum string length
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    :type  filename: str
    :param filename: (Mandatory) Specify filename where to read fuzz list
    """

    s = primitives.FromFile(value, encoding, fuzzable, max_len, name, filename)
    blocks.CURRENT.push(s)


# noinspection PyTypeChecker
def s_bit_field(value, width, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False,
                fuzzable=True, name=None):
    """
    Push a variable length bit field onto the current block stack.

    :see: Aliases: s_bit(), s_bits()

    :type  value:          int
    :param value:          Default integer value
    :type  width:          int
    :param width:          Width of bit fields
    :type  endian:         Character
    :param endian:         (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format:  str
    :param output_format format:  (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:         bool
    :param signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:     bool
    :param full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:       bool
    :param fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:           str
    :param name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    bit_field = primitives.BitField(value, width, None, endian, output_format, signed, full_range, fuzzable, name)
    blocks.CURRENT.push(bit_field)


def s_byte(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
           name=None):
    """
    Push a byte onto the current block stack.

    :see: Aliases: s_char()

    :type  value:         int|str
    :param value:         Default integer value
    :type  endian:        Character
    :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format: str
    :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:        bool
    :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:    bool
    :param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    byte = primitives.Byte(value, endian, output_format, signed, full_range, fuzzable, name)
    blocks.CURRENT.push(byte)


def s_word(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
           name=None):
    """
    Push a word onto the current block stack.

    :see: Aliases: s_short()

    :type  value:         int
    :param value:         Default integer value
    :type  endian:        chr
    :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format: str
    :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:        bool
    :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:    bool
    :param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    word = primitives.Word(value, endian, output_format, signed, full_range, fuzzable, name)
    blocks.CURRENT.push(word)


def s_dword(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
            name=None):
    """
    Push a double word onto the current block stack.

    :see: Aliases: s_long(), s_int()

    :type  value:         int
    :param value:         Default integer value
    :type  endian:        Character
    :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format: str
    :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:        bool
    :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:    bool
    :param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    dword = primitives.DWord(value, endian, output_format, signed, full_range, fuzzable, name)
    blocks.CURRENT.push(dword)


def s_qword(value, endian=LITTLE_ENDIAN, output_format="binary", signed=False, full_range=False, fuzzable=True,
            name=None):
    """
    Push a quad word onto the current block stack.

    :see: Aliases: s_double()

    :type  value:         int
    :param value:         Default integer value
    :type  endian:        Character
    :param endian:        (Optional, def=LITTLE_ENDIAN) Endianess of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format: str
    :param output_format: (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:        bool
    :param signed:        (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:    bool
    :param full_range:    (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    qword = primitives.QWord(value, endian, output_format, signed, full_range, fuzzable, name)
    blocks.CURRENT.push(qword)


# ALIASES


s_dunno = s_raw = s_unknown = s_static
s_sizer = s_size
s_bit = s_bits = s_bit_field
s_char = s_byte
s_short = s_word
s_long = s_int = s_dword
s_double = s_qword
s_repeater = s_repeat


def s_intelword(*args, **kwargs):
    defaults = {"endian": "LITTLE_ENDIAN"}
    defaults.update(kwargs)
    return s_long(*args, **defaults)


def s_intelhalfword(*args, **kwargs):
    defaults = {"endian": "LITTLE_ENDIAN"}
    defaults.update(kwargs)
    return s_short(*args, **defaults)


def s_bigword(*args, **kwargs):
    defaults = {"endian": "BIG_ENDIAN"}
    defaults.update(kwargs)
    return s_long(*args, **defaults)


def s_cstring(x):
    s_string(x)
    s_static("\x00")


# Not implemented aliases yet
def not_impl(alias, *args, **kwargs):
    raise NotImplementedError("%s isn't implemented yet. Args -> %s. Kwargs -> %s" % (alias, args, kwargs))


s_string_lf = functools.partial(not_impl, "s_string_lf")
s_string_or_env = functools.partial(not_impl, "s_string_or_env")
s_string_repeat = functools.partial(not_impl, "s_string_repeat")
s_string_variable = functools.partial(not_impl, "s_string_variable")
s_string_variables = functools.partial(not_impl, "s_string_variables")
s_binary_repeat = functools.partial(not_impl, "s_binary_repeat")
s_unistring_variable = functools.partial(not_impl, "s_unistring_variable")
s_xdr_string = functools.partial(not_impl, "s_xdr_string")


def no_sizer(*args, **kwargs):
    _ = kwargs  # just making the function univesral
    raise sex.SizerNotUtilizedError("Use the s_size primitive for including sizes. Args -> %s" % args)


# A bunch of un-defined primitives from SPIKE
s_binary_block_size_intel_halfword_plus_variable = no_sizer
s_binary_block_size_halfword_bigendian_variable = no_sizer
s_binary_block_size_word_bigendian_plussome = no_sizer
s_binary_block_size_word_bigendian_variable = no_sizer
s_binary_block_size_halfword_bigendian_mult = no_sizer
s_binary_block_size_intel_halfword_variable = no_sizer
s_binary_block_size_intel_halfword_mult = no_sizer
s_binary_block_size_intel_halfword_plus = no_sizer
s_binary_block_size_halfword_bigendian = no_sizer
s_binary_block_size_word_intel_mult_plus = no_sizer
s_binary_block_size_intel_word_variable = no_sizer
s_binary_block_size_word_bigendian_mult = no_sizer
s_blocksize_unsigned_string_variable = no_sizer
s_binary_block_size_intel_word_plus = no_sizer
s_binary_block_size_intel_halfword = no_sizer
s_binary_block_size_word_bigendian = no_sizer
s_blocksize_signed_string_variable = no_sizer
s_binary_block_size_byte_variable = no_sizer
s_binary_block_size_intel_word = no_sizer
s_binary_block_size_byte_plus = no_sizer
s_binary_block_size_byte_mult = no_sizer
s_blocksize_asciihex_variable = no_sizer
s_binary_block_size_byte = no_sizer
s_blocksize_asciihex = no_sizer
s_blocksize_string = no_sizer


# MISC


def s_hex_dump(data, addr=0):
    """
    Return the hex dump of the supplied data starting at the offset address specified.

    :type  data: Raw
    :param data: Data to show hex dump of
    :type  addr: int
    :param addr: (Optional, def=0) Offset to start displaying hex dump addresses from

    :rtype:  str
    :return: Hex dump of raw data
    """

    dump = byte_slice = ""

    for byte in data:
        if addr % 16 == 0:
            dump += " "

            for char in byte_slice:
                if 32 <= ord(char) <= 126:
                    dump += char
                else:
                    dump += "."

            dump += "\n%04x: " % addr
            byte_slice = ""

        dump += "%02x " % ord(byte)
        byte_slice += byte
        addr += 1

    remainder = addr % 16

    if remainder != 0:
        dump += "   " * (16 - remainder) + " "

    for char in byte_slice:
        if 32 <= ord(char) <= 126:
            dump += char
        else:
            dump += "."

    return dump + "\n"
