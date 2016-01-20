import hashlib
import struct
import zlib

from .. import primitives
from ..constants import LITTLE_ENDIAN
from .. import sex
from .. import helpers


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

    def _checksum(self):
        """
        Calculate and return the checksum (in raw bytes).

        Precondition: _render_dependencies() was just called.

        @rtype:  str
        @return: Checksum.
        """
        data = self._cached_block_name
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
                                                        src_addr=self._cached_ipv4_dst_block_name,
                                                        dst_addr=self._cached_ipv4_src_block_name,
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

    def _get_dummy_value(self):
        return self.checksum_lengths[self._algorithm] * '\x00'

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

        if self._block_name:
            self._recursion_flag = True
            self._cached_block_name = \
                self._request.names[self._block_name].render()
            self._recursion_flag = False
        if self._ipv4_src_block_name:
            self._recursion_flag = True
            self._cached_ipv4_src_block_name = \
                self._request.names[self._ipv4_src_block_name].render()
            self._recursion_flag = False
        if self._ipv4_dst_block_name:
            self._recursion_flag = True
            self._cached_ipv4_dst_block_name = \
                self._request.names[self._ipv4_dst_block_name].render()
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

        if self._fuzzable and self._mutant_index and not self._fuzz_complete:
            self._rendered = self._value
        elif self._recursion_flag:
            self._rendered = self._get_dummy_value()
        else:
            self._render_dependencies()
            self._rendered = self._checksum()

        return self._rendered

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
