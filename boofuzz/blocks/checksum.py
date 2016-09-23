import hashlib
import struct
import zlib
from functools import wraps

from .. import primitives
from ..constants import LITTLE_ENDIAN
from .. import sex
from .. import helpers


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


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

        self._block_name = block_name
        self._request = request
        self._algorithm = algorithm
        self._length = length
        self._endian = endian
        self._name = name
        self._ipv4_src_block_name = ipv4_src_block_name
        self._ipv4_dst_block_name = ipv4_dst_block_name

        self._fuzzable = fuzzable

        if not self._length and self._algorithm in self.checksum_lengths.iterkeys():
            self._length = self.checksum_lengths[self._algorithm]

        # Edge cases and a couple arbitrary strings (all 1s, all Es)
        self._fuzz_library = ['\x00' * self._length,
                              '\x11' * self._length,
                              '\xEE' * self._length,
                              '\xFF' * self._length,
                              '\xFF' * (self._length - 1) + '\xFE',
                              '\x00' * (self._length - 1) + '\x01']

        if self._algorithm == 'udp':
            if not self._ipv4_src_block_name:
                raise sex.SullyRuntimeError("'udp' checksum algorithm requires ipv4_src_block_name")
            if not self._ipv4_dst_block_name:
                raise sex.SullyRuntimeError("'udp' checksum algorithm requires ipv4_dst_block_name")

        self._rendered = self._get_dummy_value()

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    @property
    def name(self):
        return self._name

    def render(self):
        """
        Calculate the checksum of the specified block using the specified algorithm.
        """
        if self._should_render_fuzz_value():
            self._rendered = self._value
        elif self._recursion_flag:
            self._rendered = self._get_dummy_value()
        else:
            self._rendered = self._checksum(data=self._render_block(self._block_name),
                                            ipv4_src=self._render_block(self._ipv4_src_block_name),
                                            ipv4_dst=self._render_block(self._ipv4_dst_block_name))
        return self._rendered

    def _should_render_fuzz_value(self):
        return self._fuzzable and (self._mutant_index != 0) and not self._fuzz_complete

    def _get_dummy_value(self):
        return self.checksum_lengths[self._algorithm] * '\x00'

    @_may_recurse
    def _render_block(self, block_name):
        return self._request.names[block_name].render() if block_name is not None else None

    def _checksum(self, data, ipv4_src, ipv4_dst):
        """
        Calculate and return the checksum (in raw bytes) of data.

        :param data Data on which to calculate checksum.
        :type data str

        :rtype:  str
        :return: Checksum.
        """
        if type(self._algorithm) is str:
            if self._algorithm == "crc32":
                check = struct.pack(self._endian + "L", (zlib.crc32(data) & 0xFFFFFFFFL))

            elif self._algorithm == "adler32":
                check = struct.pack(self._endian + "L", (zlib.adler32(data) & 0xFFFFFFFFL))

            elif self._algorithm == "ipv4":
                check = struct.pack(self._endian + "H", helpers.ipv4_checksum(data))

            elif self._algorithm == "udp":
                return struct.pack(self._endian + "H",
                                   helpers.udp_checksum(msg=data,
                                                        src_addr=ipv4_src,
                                                        dst_addr=ipv4_dst,
                                                        )
                                   )

            elif self._algorithm == "md5":
                digest = hashlib.md5(data).digest()

                # TODO: is this right?
                if self._endian == ">":
                    (a, b, c, d) = struct.unpack("<LLLL", digest)
                    digest = struct.pack(">LLLL", a, b, c, d)

                check = digest

            elif self._algorithm == "sha1":
                digest = hashlib.sha1(data).digest()

                # TODO: is this right?
                if self._endian == ">":
                    (a, b, c, d, e) = struct.unpack("<LLLLL", digest)
                    digest = struct.pack(">LLLLL", a, b, c, d, e)

                check = digest

            else:
                raise sex.SullyRuntimeError("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self._algorithm)
        else:
            check = self._algorithm(data)

        if self._length:
            return check[:self._length]
        else:
            return check

    @property
    def original_value(self):
        if self._recursion_flag:
            return self._get_dummy_value()
        else:
            return self._checksum(data=self._original_value_of_block(self._block_name),
                                  ipv4_src=self._original_value_of_block(self._ipv4_src_block_name),
                                  ipv4_dst=self._original_value_of_block(self._ipv4_dst_block_name))

    @_may_recurse
    def _original_value_of_block(self, block_name):
        return self._request.names[block_name].original_value if block_name is not None else None

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self._length

    def __nonzero__(self):
        """
        Make sure instances evaluate to True even if __len__ is zero.

        :return: True
        """
        return True
