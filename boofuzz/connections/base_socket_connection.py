from __future__ import absolute_import

import abc
import math
import os
import socket
import struct

from future.utils import with_metaclass

from boofuzz.connections import itarget_connection


def _seconds_to_sockopt_format(seconds):
    """Convert floating point seconds value to second/useconds struct used by UNIX socket library.
    For Windows, convert to whole milliseconds.
    """
    if os.name == "nt":
        return int(seconds * 1000)
    else:
        microseconds_per_second = 1000000
        whole_seconds = int(math.floor(seconds))
        whole_microseconds = int(math.floor((seconds % 1) * microseconds_per_second))
        return struct.pack("ll", whole_seconds, whole_microseconds)


class BaseSocketConnection(with_metaclass(abc.ABCMeta, itarget_connection.ITargetConnection)):
    """This class serves as a base for a number of Connections over sockets.

    .. versionadded:: 0.2.0

    Args:
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
    """

    def __init__(self, send_timeout, recv_timeout):
        self._send_timeout = send_timeout
        self._recv_timeout = recv_timeout

        self._sock = None

    def close(self):
        """
        Close connection to the target.

        Returns:
            None
        """
        self._sock.close()

    @abc.abstractmethod
    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        Returns:
            None
        """
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _seconds_to_sockopt_format(self._send_timeout))
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _seconds_to_sockopt_format(self._recv_timeout))
