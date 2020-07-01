from __future__ import absolute_import

import ctypes
import errno
import platform
import socket
import sys

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection, ip_constants


class UDPSocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with UDP Sockets.

    .. versionadded:: 0.2.0

    Args:
        host (str): Hostname or IP adress of target system.
        port (int): Port of target service.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        server (bool): Set to True to enable server side fuzzing.
        bind (tuple (host, port)): Socket bind address and port. Required if using recv().
        broadcast (bool): Set to True to enable UDP broadcast. Must supply appropriate broadcast address for send()
            to work, and '' for bind host for recv() to work.
    """

    _max_payload = None

    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, server=False, bind=None, broadcast=False):
        super(UDPSocketConnection, self).__init__(send_timeout, recv_timeout)

        self.host = host
        self.port = port
        self.server = server
        self.bind = bind
        self.broadcast = broadcast

        self._serverSock = None
        self._udp_client_port = None

        self.max_payload()

        if self.bind and self.server:
            raise Exception("You cannot set both bind and server at the same time.")

    def open(self):
        """Opens connection to the target. Make sure to call close!

        Returns:
            None
        """

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if self.bind:
            self._sock.bind(self.bind)

        if self.broadcast:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

        super(UDPSocketConnection, self).open()

        if self.server:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))

    def recv(self, max_bytes):
        """Receive up to max_bytes data from the target.

        Args:
            max_bytes(int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        data = b""

        try:
            if self.bind or self.server:
                data, self._udp_client_port = self._sock.recvfrom(max_bytes)
            else:
                raise exception.SullyRuntimeError(
                    "UDPSocketConnection.recv() requires a bind address/port." " Current value: {}".format(self.bind)
                )
        except socket.timeout:
            data = b""
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise_(
                    exception.BoofuzzTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                    None,
                    sys.exc_info()[2],
                )
            elif e.errno in [errno.ECONNRESET, errno.ENETRESET, errno.ETIMEDOUT]:
                raise_(exception.BoofuzzTargetConnectionReset(), None, sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK:
                data = b""
            else:
                raise

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!
        Some protocols will truncate; see self.MAX_PAYLOADS.

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0
        data = data[: self._max_payload]

        try:
            if self.server:
                if self._udp_client_port is None:
                    raise exception.BoofuzzError("recv() must be called before send with udp fuzzing servers.")

                num_sent = self._sock.sendto(data, self._udp_client_port)
            else:
                num_sent = self._sock.sendto(data, (self.host, self.port))
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise_(
                    exception.BoofuzzTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                    None,
                    sys.exc_info()[2],
                )
            elif e.errno in [errno.ECONNRESET, errno.ENETRESET, errno.ETIMEDOUT, errno.EPIPE]:
                raise_(exception.BoofuzzTargetConnectionReset(), None, sys.exc_info()[2])
            else:
                raise

        return num_sent

    @classmethod
    def max_payload(cls):
        """Returns the maximum payload this connection can send at once.

        This performs some crazy CTypes magic to do a getsockopt() which determines the max UDP payload size
        in a platform-agnostic way.

        Returns:
            int: The maximum length of a UDP packet the current platform supports
        """

        # Compute max payload on first access, then re-use the cached value.
        # This code was in helpers.py, but is after the splitting of the
        # SocketConnection class more appropriate here.

        if cls._max_payload is not None:
            return cls._max_payload

        windows = platform.uname()[0] == "Windows"
        mac = platform.uname()[0] == "Darwin"
        linux = platform.uname()[0] == "Linux"
        openbsd = platform.uname()[0] == "OpenBSD"
        lib = None

        # pytype: disable=attribute-error,module-attr
        if windows:
            sol_socket = ctypes.c_int(0xFFFF)
            sol_max_msg_size = 0x2003
            lib = ctypes.WinDLL("Ws2_32.dll")
            opt = ctypes.c_int(sol_max_msg_size)
        elif linux or mac or openbsd:
            if mac:
                lib = ctypes.cdll.LoadLibrary("libc.dylib")
            elif linux:
                lib = ctypes.cdll.LoadLibrary("libc.so.6")
            elif openbsd:
                lib = ctypes.cdll.LoadLibrary("libc.so")
            sol_socket = ctypes.c_int(socket.SOL_SOCKET)
            opt = ctypes.c_int(socket.SO_SNDBUF)

        else:
            raise Exception("Unknown platform!")

        ulong_size = ctypes.sizeof(ctypes.c_ulong)
        buf = ctypes.create_string_buffer(ulong_size)
        bufsize = ctypes.c_int(ulong_size)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        lib.getsockopt(sock.fileno(), sol_socket, opt, buf, ctypes.pointer(bufsize))
        # pytype: enable=attribute-error,module-attr

        # Sanity filter against UDP_MAX_PAYLOAD_IPV4_THEORETICAL
        cls._max_payload = min(ctypes.c_ulong.from_buffer(buf).value, ip_constants.UDP_MAX_PAYLOAD_IPV4_THEORETICAL)

        return cls._max_payload

    @property
    def info(self):
        return "{0}:{1}".format(self.host, self.port)
