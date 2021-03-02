from __future__ import absolute_import

import functools
import sys

import six
from past.builtins import map

from . import blocks, exception, legos, primitives
from .blocks import Aligned, Block, Checksum, Repeat, Request, REQUESTS, Size
from .connections import (
    BaseSocketConnection,
    FileConnection,
    ip_constants,
    ISerialLike,
    ITargetConnection,
    RawL2SocketConnection,
    RawL3SocketConnection,
    SerialConnection,
    SerialConnectionLowLevel,
    SocketConnection,
    SSLSocketConnection,
    TCPSocketConnection,
    UDPSocketConnection,
    UnixSocketConnection,
)
from .constants import BIG_ENDIAN, DEFAULT_PROCMON_PORT, LITTLE_ENDIAN
from .event_hook import EventHook
from .exception import BoofuzzFailure, MustImplementException, SizerNotUtilizedError, SullyRuntimeError
from .fuzz_logger import FuzzLogger
from .fuzz_logger_csv import FuzzLoggerCsv
from .fuzz_logger_curses import FuzzLoggerCurses
from .fuzz_logger_text import FuzzLoggerText
from .fuzzable import Fuzzable
from .fuzzable_block import FuzzableBlock
from .ifuzz_logger import IFuzzLogger
from .ifuzz_logger_backend import IFuzzLoggerBackend
from .monitors import BaseMonitor, CallbackMonitor, NetworkMonitor, pedrpc, ProcessMonitor
from .utils.process_monitor_local import ProcessMonitorLocal
from .primitives import (
    BasePrimitive,
    BitField,
    Byte,
    Bytes,
    Delim,
    DWord,
    FromFile,
    Group,
    Mirror,
    QWord,
    RandomData,
    Static,
    String,
    Word,
)
from .repeater import CountRepeater, Repeater, TimeRepeater
from .sessions import open_test_run, Session, Target
from .protocol_session import ProtocolSession
from .protocol_session_reference import ProtocolSessionReference

# workaround to make Tornado work in Python 3.8
# https://github.com/tornadoweb/tornado/issues/2608
if sys.platform == "win32" and sys.version_info >= (3, 8):
    import asyncio

    # noinspection PyUnresolvedReferences
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # pytype: disable=module-attr

__all__ = [
    "Aligned",
    "BaseMonitor",
    "BasePrimitive",
    "BaseSocketConnection",
    "BIG_ENDIAN",
    "BitField",
    "Block",
    "blocks",
    "BoofuzzFailure",
    "Byte",
    "Bytes",
    "CallbackMonitor",
    "Checksum",
    "CountRepeater",
    "DEFAULT_PROCMON_PORT",
    "Delim",
    "DWord",
    "EventHook",
    "exception",
    "FileConnection",
    "FromFile",
    "Fuzzable",
    "FuzzableBlock",
    "FuzzLogger",
    "FuzzLoggerCsv",
    "FuzzLoggerCurses",
    "FuzzLoggerText",
    "Group",
    "IFuzzLogger",
    "IFuzzLoggerBackend",
    "ip_constants",
    "ISerialLike",
    "ITargetConnection",
    "legos",
    "LITTLE_ENDIAN",
    "Mirror",
    "MustImplementException",
    "NetworkMonitor",
    "open_test_run",
    "pedrpc",
    "primitives",
    "ProcessMonitor",
    "ProcessMonitorLocal",
    "QWord",
    "RandomData",
    "RawL2SocketConnection",
    "RawL3SocketConnection",
    "Repeat",
    "Repeater",
    "Request",
    "REQUESTS",
    "s_aligned",
    "s_bigword",
    "s_binary",
    "s_bit",
    "s_bit_field",
    "s_bits",
    "s_block",
    "s_block_end",
    "s_block_start",
    "s_byte",
    "s_bytes",
    "s_char",
    "s_checksum",
    "s_cstring",
    "s_delim",
    "s_double",
    "s_dunno",
    "s_dword",
    "s_from_file",
    "s_get",
    "s_group",
    "s_hex_dump",
    "s_initialize",
    "s_int",
    "s_intelword",
    "s_lego",
    "s_long",
    "s_mirror",
    "s_num_mutations",
    "s_qword",
    "s_random",
    "s_raw",
    "s_repeat",
    "s_repeater",
    "s_short",
    "s_size",
    "s_sizer",
    "s_static",
    "s_string",
    "s_switch",
    "s_unknown",
    "s_update",
    "s_word",
    "SerialConnection",
    "SerialConnectionLowLevel",
    "Session",
    "Size",
    "SizerNotUtilizedError",
    "SocketConnection",
    "SSLSocketConnection",
    "Static",
    "String",
    "SullyRuntimeError",
    "Target",
    "TCPSocketConnection",
    "ProtocolSession",
    "ProtocolSessionReference",
    "TimeRepeater",
    "UDPSocketConnection",
    "UnixSocketConnection",
    "Word",
]

__version__ = "0.3.0"


# REQUEST MANAGEMENT
def s_get(name=None):
    """
    Return the request with the specified name or the current request if name is not specified. Use this to switch from
    global function style request manipulation to direct object manipulation. Example::

        req = s_get("HTTP BASIC")
        print(req.num_mutations())

    The selected request is also set as the default current. (ie: s_switch(name) is implied).

    :type  name: str
    :param name: (Optional, def=None) Name of request to return or current request if name is None.

    :rtype:  blocks.Request
    :return: The requested request.
    """

    if not name:
        return blocks.CURRENT

    # ensure this gotten request is the new current.
    s_switch(name)

    if name not in blocks.REQUESTS:
        raise exception.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    return blocks.REQUESTS[name]


def s_initialize(name):
    """
    Initialize a new block request. All blocks / primitives generated after this call apply to the named request.
    Use s_switch() to jump between factories.

    :type  name: str
    :param name: Name of request
    """
    if name in blocks.REQUESTS:
        raise exception.SullyRuntimeError("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    blocks.REQUESTS[name] = Request(name)
    blocks.CURRENT = blocks.REQUESTS[name]


def s_num_mutations():
    """
    Determine the number of repetitions we will be making.

    :rtype:  int
    :return: Number of mutated forms this primitive can take.
    """

    return blocks.CURRENT.get_num_mutations()


def s_switch(name):
    """
    Change the current request to the one specified by "name".

    :type  name: str
    :param name: Name of request
    """

    if name not in blocks.REQUESTS:
        raise exception.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    blocks.CURRENT = blocks.REQUESTS[name]


# ## BLOCK MANAGEMENT


def s_block(name=None, group=None, encoder=None, dep=None, dep_value=None, dep_values=None, dep_compare="=="):
    """
    Open a new block under the current request. The returned instance supports the "with" interface so it will
    be automatically closed for you::

        with s_block("header"):
            s_static("\\x00\\x01")
            if s_block_start("body"):
                ...

    :type  name:        str, optional
    :param name:        Name of block being opened
    :type  group:       str, optional
    :param group:       (Optional, def=None) Name of group to associate this block with
    :type  encoder:     Function Pointer, optional
    :param encoder:     (Optional, def=None) Optional pointer to a function to pass rendered data to prior to return
    :type  dep:         str, optional
    :param dep:         (Optional, def=None) Optional primitive whose specific value this block is dependant on
    :type  dep_value:   Mixed, optional
    :param dep_value:   (Optional, def=None) Value that field "dep" must contain for block to be rendered
    :type  dep_values:  List of Mixed Types, optional
    :param dep_values:  (Optional, def=None) Values that field "dep" may contain for block to be rendered
    :type  dep_compare: str, optional
    :param dep_compare: (Optional, def="==") Comparison method to use on dependency (==, !=, >, >=, <, <=)
    """

    class ScopedBlock(object):
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

    block = s_block_start(
        name,
        request=blocks.CURRENT,
        group=group,
        encoder=encoder,
        dep=dep,
        dep_value=dep_value,
        dep_values=dep_values,
        dep_compare=dep_compare,
    )

    return ScopedBlock(block)


def s_aligned(modulus=1, pattern=b"\x00", name=None):
    """FuzzableBlock that aligns its contents to a certain number of bytes

    :type  modulus:     int, optional
    :param modulus:     Pad length of child content to this many bytes, defaults to 1
    :type  pattern:     bytes, optional
    :param pattern:     Pad using these byte(s)
    :type  name:        str, optional
    :param name:        Name, for referencing later. Names should always be provided, but if not, a default name will
                        be given, defaults to None
    """

    class ScopedAligned(object):
        def __init__(self, aligned):
            self.aligned = aligned

        def __enter__(self):
            """
            Setup before entering the "with" statement body
            """
            return self.aligned

        def __exit__(self, type, value, traceback):
            """
            Cleanup after executing the "with" statement body
            """
            blocks.CURRENT.pop()

    aligned = Aligned(name=name, modulus=modulus, pattern=pattern, fuzzable=True)
    blocks.CURRENT.push(aligned)

    return ScopedAligned(aligned)


def s_block_start(name=None, *args, **kwargs):
    """
    Open a new block under the current request. This routine always returns an instance so you can make your fuzzer
    pretty with indenting::

        if s_block_start("header"):
            s_static("\\x00\\x01")
            if s_block_start("body"):
                ...
        s_block_close()

    :note Prefer using s_block to this function directly
    :see s_block
    """
    block = Block(name=name, *args, **kwargs)
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


def s_checksum(
    block_name=None,
    algorithm="crc32",
    length=0,
    endian=LITTLE_ENDIAN,
    fuzzable=True,
    name=None,
    ipv4_src_block_name=None,
    ipv4_dst_block_name=None,
):
    """
    Checksum bound to the block with the specified name.

    The algorithm may be chosen by name with the algorithm parameter, or a custom function may be specified with
    the algorithm parameter.

    The length field is only necessary for custom algorithms.

    Recursive checksums are supported; the checksum field itself will render as all zeros for the sake of checksum
    or length calculations.

    :type  block_name: str, optional
    :param block_name: Name of target block for checksum calculations.
    :type  algorithm: str, function, optional
    :param algorithm: Checksum algorithm to use. (crc32, crc32c, adler32, md5, sha1, ipv4, udp)
        Pass a function to use a custom algorithm. This function has to take and return byte-type data,
        defaults to crc32
    :type  length: int, optional
    :param length: Length of checksum, auto-calculated by default. Must be specified manually when using custom
        algorithm, defaults to 0
    :type  endian: chr, optional
    :param endian: Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  fuzzable:   bool, optional
    :param fuzzable:   Enable/disable fuzzing.
    :type  name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  ipv4_src_block_name: str, optional
    :param ipv4_src_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 source address,
        defaults to None
    :type  ipv4_dst_block_name: str, optional
    :param ipv4_dst_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 destination address,
        defaults to None
    """

    # you can't add a checksum for a block currently in the stack.
    if block_name in blocks.CURRENT.block_stack:
        raise exception.SullyRuntimeError("CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")

    checksum = Checksum(
        name=name,
        block_name=block_name,
        request=blocks.CURRENT,
        algorithm=algorithm,
        length=length,
        endian=endian,
        fuzzable=fuzzable,
        ipv4_src_block_name=ipv4_src_block_name,
        ipv4_dst_block_name=ipv4_dst_block_name,
    )
    blocks.CURRENT.push(checksum)


def s_repeat(block_name=None, min_reps=0, max_reps=25, step=1, variable=None, fuzzable=True, name=None):
    """
    Repeat the rendered contents of the specified block cycling from min_reps to max_reps counting by step. By
    default renders to nothing. This block modifier is useful for fuzzing overflows in table entries. This block
    modifier MUST come after the block it is being applied to.

    :see: Aliases: s_repeater()

    :type  block_name: str
    :param block_name: (Optional, def=None) Name of block to repeat
    :type  min_reps:   int
    :param min_reps:   (Optional, def=0) Minimum number of block repetitions
    :type  max_reps:   int
    :param max_reps:   (Optional, def=25) Maximum number of block repetitions
    :type  step:       int
    :param step:       (Optional, def=1) Step count between min and max reps
    :type  variable:   Sulley Integer Primitive
    :param variable:   (Optional, def=None) An integer primitive which will specify the number of repitions
    :type  fuzzable:   bool
    :param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:       str
    :param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(
        Repeat(
            name=name,
            block_name=block_name,
            request=blocks.CURRENT,
            min_reps=min_reps,
            max_reps=max_reps,
            step=step,
            variable=variable,
            fuzzable=fuzzable,
        )
    )


def s_size(
    block_name=None,
    offset=0,
    length=4,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    inclusive=False,
    signed=False,
    math=None,
    fuzzable=True,
    name=None,
):
    """
    Create a sizer block bound to the block with the specified name. You *can not* create a sizer for any
    currently open blocks.

    :see: Aliases: s_sizer()

    :type  block_name:    str, optional
    :param block_name:    Name of block to apply sizer to.
    :type  offset:        int, optional
    :param offset:        Offset for calculated size value, defaults to 0
    :type  length:        int, optional
    :param length:        Length of sizer, defaults to 4
    :type  endian:        chr, optional
    :param endian:        Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  output_format: str, optional
    :param output_format: Output format, "binary" or "ascii", defaults to binary
    :type  inclusive:     bool, optional
    :param inclusive:     Should the sizer count its own length? Defaults to False
    :type  signed:        bool, optional
    :param signed:        Make size signed vs. unsigned (applicable only with format="ascii"), defaults to False
    :type  math:          def, optional
    :param math:          Apply the mathematical op defined in this function to the size, defaults to None
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this sizer
    :type  name:          str
    :param name:          Name of this sizer field
    """

    blocks.CURRENT.push(
        Size(
            name=name,
            block_name=block_name,
            request=blocks.CURRENT,
            offset=offset,
            length=length,
            endian=endian,
            output_format=output_format,
            inclusive=inclusive,
            signed=signed,
            math=math,
            fuzzable=fuzzable,
        )
    )


def s_update(name, value):
    """
    Update the value of the named primitive in the currently open request.

    :type  name:  str
    :param name:  Name of object whose value we wish to update
    :type  value: Mixed
    :param value: Updated value
    """

    if name not in map(lambda o: o.name, blocks.CURRENT.walk()):
        raise exception.SullyRuntimeError("NO OBJECT WITH NAME '%s' FOUND IN CURRENT REQUEST" % name)

    blocks.CURRENT.names[name]._value = value


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

    value = b""
    while parsed:
        pair = parsed[:2]
        parsed = parsed[2:]

        value += six.int2byte(int(pair, 16))

    blocks.CURRENT.push(Static(name=name, default_value=parsed, fuzzable=False))


def s_delim(value=" ", fuzzable=True, name=None):
    """
    Push a delimiter onto the current block stack.

    :type  value:    Character
    :param value:    (Optional, def=" ")Original value
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(Delim(name=name, default_value=value, fuzzable=fuzzable))


def s_group(name=None, values=None, default_value=None):
    """
    This primitive represents a list of static values, stepping through each one on mutation. You can tie a block
    to a group primitive to specify that the block should cycle through all possible mutations for *each* value
    within the group. The group primitive is useful for example for representing a list of valid opcodes.

    :type  name:            str
    :param name:            (Optional, def=None) Name of group
    :type  values:          List or raw data
    :param values:          (Optional, def=None) List of possible raw values this group can take.
    :type  default_value:   str or bytes
    :param default_value:   (Optional, def=None) Specifying a value when fuzzing() is complete
    """

    blocks.CURRENT.push(Group(name=name, default_value=default_value, values=values))


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
        raise exception.SullyRuntimeError("INVALID LEGO TYPE SPECIFIED: %s" % lego_type)
    lego = legos.BIN[lego_type](name, blocks.CURRENT, value, options)

    # push the lego onto the stack and immediately pop to close the block.
    blocks.CURRENT.push(lego)
    blocks.CURRENT.pop()


def s_random(value="", min_length=0, max_length=1, num_mutations=25, fuzzable=True, step=None, name=None):
    """
    Generate a random chunk of data while maintaining a copy of the original. A random length range can be specified.
    For a static length, set min/max length to be the same.

    :type  value:         str or bytes
    :param value:         (Optional, def="") Original value
    :type  min_length:    int
    :param min_length:    (Optional, def=0) Minimum length of random block
    :type  max_length:    int
    :param max_length:    (Optional, def=1) Maximum length of random block
    :type  num_mutations: int
    :param num_mutations: (Optional, def=25) Number of mutations to make before reverting to default
    :type  fuzzable:      bool
    :param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  step:          int
    :param step:          (Optional, def=None) If not null, step count between min and max reps, otherwise random
    :type  name:          str
    :param name:          (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(
        RandomData(
            name=name,
            default_value=value,
            min_length=min_length,
            max_length=max_length,
            max_mutations=num_mutations,
            step=step,
            fuzzable=fuzzable,
        )
    )


def s_static(value=None, name=None):
    """
    Push a static value onto the current block stack.

    :see: Aliases: s_dunno(), s_raw(), s_unknown()

    :type  value: Raw
    :param value: Raw static data
    :type  name:  str
    :param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(Static(name=name, default_value=value))


def s_mirror(primitive_name=None, name=None):
    """
    Push a mirror of another primitive onto the current block stack.

    :type primitive_name:   str
    :param primitive_name:  (Optional, def=None) Name of target primitive
    :type name:             str
    :param name:            (Optional, def=None) Name of current primitive
    """
    blocks.CURRENT.push(Mirror(name=name, primitive_name=primitive_name, request=blocks.CURRENT))


def s_string(value="", size=None, padding=b"\x00", encoding="ascii", fuzzable=True, max_len=None, name=None):
    """
    Push a string onto the current block stack.

    :type  value:    str
    :param value:    (Optional, def="")Default string value
    :type  size:     int
    :param size:     (Optional, def=None) Static size of this field, leave None for dynamic.
    :type  padding:  Character
    :param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
    :type  encoding: str
    :param encoding: (Optional, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  max_len:  int
    :param max_len:  (Optional, def=None) Maximum string length
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    # support old interface where default was -1 instead of None
    if size == -1:
        size = None
    if max_len == -1:
        max_len = None

    blocks.CURRENT.push(
        String(
            name=name,
            default_value=value,
            size=size,
            padding=padding,
            encoding=encoding,
            max_len=max_len,
            fuzzable=fuzzable,
        )
    )


def s_from_file(value="", filename=None, encoding="ascii", fuzzable=True, max_len=0, name=None):
    """
    Push a value from file onto the current block stack.

    :type  value:    str
    :param value:    (Optional, def="") Default string value
    :type  filename: str
    :param filename: (Optional, def=None) Filename pattern to load all fuzz value
    :type  encoding: str
    :param encoding: (DEPRECIATED, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    :type  fuzzable: bool
    :param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  max_len:  int
    :param max_len:  (Optional, def=0) Maximum string length
    :type  name:     str
    :param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(FromFile(name=name, default_value=value, max_len=max_len, filename=filename, fuzzable=fuzzable))


# noinspection PyTypeChecker
def s_bit_field(
    value=0,
    width=8,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None,
    fuzz_values=None,
):
    """
    Push a variable length bit field onto the current block stack.

    :see: Aliases: s_bit(), s_bits()

    :type  value:          int
    :param value:          (Optional, def=0) Default integer value
    :type  width:          int
    :param width:          (Optional, def=8) Width of bit fields
    :type  endian:         Character
    :param endian:         (Optional, def=LITTLE_ENDIAN) Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    :type  output_format:  str
    :param output_format:  (Optional, def=binary) Output format, "binary" or "ascii"
    :type  signed:         bool
    :param signed:         (Optional, def=False) Make size signed vs. unsigned (applicable only with format="ascii")
    :type  full_range:     bool
    :param full_range:     (Optional, def=False) If enabled the field mutates through *all* possible values.
    :type  fuzzable:       bool
    :param fuzzable:       (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  name:           str
    :param name:           (Optional, def=None) Specifying a name gives you direct access to a primitive
    :type fuzz_values:     list
    :param fuzz_values:    List of custom fuzz values to add to the normal mutations.
    """

    blocks.CURRENT.push(
        BitField(
            name=name,
            default_value=value,
            width=width,
            endian=endian,
            output_format=output_format,
            signed=signed,
            full_range=full_range,
            fuzzable=fuzzable,
            fuzz_values=fuzz_values,
        )
    )


def s_byte(
    value=0,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None,
    fuzz_values=None,
):
    """
    Push a byte onto the current block stack.

    :see: Aliases: s_char()

    :type  value:         int|byte
    :param value:         (Optional, def=0) Default integer value
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
    :type fuzz_values:    list
    :param fuzz_values:   List of custom fuzz values to add to the normal mutations.
    """

    blocks.CURRENT.push(
        Byte(
            endian=endian,
            output_format=output_format,
            signed=signed,
            full_range=full_range,
            name=name,
            default_value=value,
            fuzzable=fuzzable,
            fuzz_values=fuzz_values,
        )
    )


def s_bytes(value=b"", size=None, padding=b"\x00", fuzzable=True, max_len=None, name=None):
    """
    Push a bytes field of arbitrary length onto the current block stack.

    :type  value:        bytes
    :param value:        (Optional, def=b"")Default binary value
    :type  size:         int
    :param size:         (Optional, def=None) Static size of this field, leave None for dynamic.
    :type  padding:      chr
    :param padding:      (Optional, def=b"\\x00") Value to use as padding to fill static field size.
    :type  fuzzable:     bool
    :param fuzzable:     (Optional, def=True) Enable/disable fuzzing of this primitive
    :type  max_len:      int
    :param max_len:      (Optional, def=None) Maximum string length
    :type  name:         str
    :param name:         (Optional, def=None) Specifying a name gives you direct access to a primitive
    """

    blocks.CURRENT.push(
        Bytes(name=name, default_value=value, size=size, padding=padding, max_len=max_len, fuzzable=fuzzable)
    )


def s_word(
    value=0,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None,
    fuzz_values=None,
):
    """
    Push a word onto the current block stack.

    :see: Aliases: s_short()

    :type  value:         (Optional, def=0) int
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
    :type fuzz_values:    list
    :param fuzz_values:   List of custom fuzz values to add to the normal mutations.
    """

    blocks.CURRENT.push(
        Word(
            endian=endian,
            output_format=output_format,
            signed=signed,
            full_range=full_range,
            name=name,
            default_value=value,
            fuzzable=fuzzable,
            fuzz_values=fuzz_values,
        )
    )


def s_dword(
    value=0,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None,
    fuzz_values=None,
):
    """
    Push a double word onto the current block stack.

    :see: Aliases: s_long(), s_int()

    :type  value:         (Optional, def=0) int
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
    :type fuzz_values:    list
    :param fuzz_values:   List of custom fuzz values to add to the normal mutations.
    """

    blocks.CURRENT.push(
        DWord(
            endian=endian,
            output_format=output_format,
            signed=signed,
            full_range=full_range,
            name=name,
            default_value=value,
            fuzzable=fuzzable,
            fuzz_values=fuzz_values,
        )
    )


def s_qword(
    value=0,
    endian=LITTLE_ENDIAN,
    output_format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None,
    fuzz_values=None,
):
    """
    Push a quad word onto the current block stack.

    :see: Aliases: s_double()

    :type  value:         (Optional, def=0) int
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
    :type fuzz_values:    list
    :param fuzz_values:   List of custom fuzz values to add to the normal mutations.
    """

    blocks.CURRENT.push(
        QWord(
            endian=endian,
            output_format=output_format,
            signed=signed,
            full_range=full_range,
            name=name,
            default_value=value,
            fuzzable=fuzzable,
            fuzz_values=fuzz_values,
        )
    )


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
    raise exception.SizerNotUtilizedError("Use the s_size primitive for including sizes. Args -> %s" % args)


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
