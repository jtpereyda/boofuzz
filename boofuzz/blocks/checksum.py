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
    """
    Checksum bound to the block with the specified name.

    The algorithm may be chosen by name with the algorithm parameter, or a custom function may be specified with
    the algorithm parameter.

    The length field is only necessary for custom algorithms.

    Recursive checksums are supported; the checksum field itself will render as all zeros for the sake of checksum
    or length calculations.

    Args:
        block_name (str): Name of target block for checksum calculations.
        request (s_request): Request this block belongs to.
        algorithm (Union[str, function], optional): Checksum algorithm to use. (crc32, adler32, md5, sha1, ipv4, udp)
        length (int, optional): Length of checksum, auto-calculated by default.
            Must be specified manually when using custom algorithm.
        endian (str, optional): Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >).
            Defaults to LITTLE_ENDIAN.
        fuzzable (bool, optional): Enable/disable fuzzing. Defaults to true.
        name (str): Name of this checksum field
        ipv4_src_block_name (str): Required for 'udp' algorithm. Name of block yielding IPv4 source address.
        ipv4_dst_block_name (str): Required for 'udp' algorithm. Name of block yielding IPv4 destination address.
    """
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
        if self._length:
            return self._length * '\x00'
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
