import hashlib
import struct
import warnings
import zlib
from functools import wraps

import six

from .. import exception, helpers, primitives
from ..constants import LITTLE_ENDIAN


def _may_recurse(f):
    @wraps(f)
    def safe_recurse(self, *args, **kwargs):
        self._recursion_flag = True
        result = f(self, *args, **kwargs)
        self._recursion_flag = False
        return result

    return safe_recurse


class Checksum(primitives.BasePrimitive):
    """Checksum bound to the block with the specified name.

    The algorithm may be chosen by name with the algorithm parameter, or a custom function may be specified with
    the algorithm parameter.

    The length field is only necessary for custom algorithms.

    Recursive checksums are supported; the checksum field itself will render as all zeros for the sake of checksum
    or length calculations.

    :type  name: str, optional
    :param name: Name, for referencing later. Names should always be provided, but if not, a default name will be given,
        defaults to None
    :type  block_name: str
    :param block_name: Name of target block for checksum calculations.
    :type  request: boofuzz.Request, optional
    :param request: Request this block belongs to.
    :type  algorithm: str, function, optional
    :param algorithm: Checksum algorithm to use. (crc32, crc32c, adler32, md5, sha1, ipv4, udp)
        Pass a function to use a custom algorithm. This function has to take and return byte-type data,
        defaults to crc32
    :type  length: int, optional
    :param length: Length of checksum, auto-calculated by default. Must be specified manually when using custom
        algorithm, defaults to 0
    :type  endian: chr, optional
    :param endian: Endianness of the bit field (LITTLE_ENDIAN: <, BIG_ENDIAN: >), defaults to LITTLE_ENDIAN
    :type  ipv4_src_block_name: str, optional
    :param ipv4_src_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 source address,
        defaults to None
    :type  ipv4_dst_block_name: str, optional
    :param ipv4_dst_block_name: Required for 'udp' algorithm. Name of block yielding IPv4 destination address,
        defaults to None
    :type  fuzzable: bool, optional
    :param fuzzable: Enable/disable fuzzing of this block, defaults to true
    """

    checksum_lengths = {"crc32": 4, "crc32c": 4, "adler32": 4, "md5": 16, "sha1": 20, "ipv4": 2, "udp": 2}

    def __init__(
        self,
        name=None,
        block_name=None,
        request=None,
        algorithm="crc32",
        length=0,
        endian=LITTLE_ENDIAN,
        ipv4_src_block_name=None,
        ipv4_dst_block_name=None,
        *args,
        **kwargs
    ):
        super(Checksum, self).__init__(name=name, *args, **kwargs)

        self._block_name = block_name
        self._request = request
        self._algorithm = algorithm
        self._length = length
        self._endian = endian
        self._ipv4_src_block_name = ipv4_src_block_name
        self._ipv4_dst_block_name = ipv4_dst_block_name

        if not self._length and self._algorithm in self.checksum_lengths:
            self._length = self.checksum_lengths[self._algorithm]

        # Edge cases and a couple arbitrary strings (all 1s, all Es)
        self._fuzz_library = [
            b"\x00" * self._length,
            b"\x11" * self._length,
            b"\xEE" * self._length,
            b"\xFF" * self._length,
            b"\xFF" * (self._length - 1) + b"\xFE",
            b"\x00" * (self._length - 1) + b"\x01",
        ]

        if self._algorithm == "udp":
            if not self._ipv4_src_block_name:
                raise exception.SullyRuntimeError("'udp' checksum algorithm requires ipv4_src_block_name")
            if not self._ipv4_dst_block_name:
                raise exception.SullyRuntimeError("'udp' checksum algorithm requires ipv4_dst_block_name")

        self._rendered = self._get_dummy_value()

        # Set the recursion flag before calling a method that may cause a recursive loop.
        self._recursion_flag = False

    def encode(self, value, mutation_context):
        if value is None:
            if self._recursion_flag or self._request is None:
                self._rendered = self._get_dummy_value()
            else:
                self._rendered = self._checksum(
                    data=self._render_block(self._block_name, mutation_context=mutation_context),
                    ipv4_src=self._render_block(self._ipv4_src_block_name, mutation_context=mutation_context),
                    ipv4_dst=self._render_block(self._ipv4_dst_block_name, mutation_context=mutation_context),
                )
            return helpers.str_to_bytes(self._rendered)
        else:
            return value

    def _get_dummy_value(self):
        return self._length * "\x00"

    @_may_recurse
    def _render_block(self, block_name, mutation_context):
        return (
            self._request.resolve_name(self.context_path, block_name).render(mutation_context=mutation_context)
            if block_name is not None and self._request is not None
            else None
        )

    def _checksum(self, data, ipv4_src, ipv4_dst):
        """
        Calculate and return the checksum (in raw bytes) of data.

        :param data Data on which to calculate checksum.
        :type data bytes

        :rtype:  bytes
        :return: Checksum.
        """
        if isinstance(self._algorithm, six.string_types):
            if self._algorithm == "crc32":
                check = struct.pack(self._endian + "L", (zlib.crc32(data) & 0xFFFFFFFF))

            elif self._algorithm == "crc32c":
                try:
                    import crc32c  # pytype: disable=import-error
                except ImportError:
                    warnings.warn(
                        "Importing crc32c package failed. Please install it using pip.", UserWarning, stacklevel=2
                    )
                    raise
                check = struct.pack(self._endian + "L", crc32c.crc32(data))

            elif self._algorithm == "adler32":
                check = struct.pack(self._endian + "L", (zlib.adler32(data) & 0xFFFFFFFF))

            elif self._algorithm == "ipv4":
                check = struct.pack(self._endian + "H", helpers.ipv4_checksum(data))

            elif self._algorithm == "udp":
                return struct.pack(
                    self._endian + "H", helpers.udp_checksum(msg=data, src_addr=ipv4_src, dst_addr=ipv4_dst)
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
                raise exception.SullyRuntimeError("INVALID CHECKSUM ALGORITHM SPECIFIED: %s" % self._algorithm)
        else:
            check = self._algorithm(data)

        if self._length:
            return check[: self._length]
        else:
            return check

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    def __len__(self):
        return self._length
