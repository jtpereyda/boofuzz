from __future__ import absolute_import

import errno
import socket
import sys

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection


class RawL2SocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with Raw Layer 2 Sockets.

    .. versionadded:: 0.2.0

    Args:
        interface (str): Hostname or IP adress of target system.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        ethernet_proto (int): Ethernet protocol to bind to. If supplied, the opened socket
            gets bound to this protocol, otherwise the python default of 0 is used. Must
            be supplied if this socket should be used for receiving. For valid options,
            see <net/if_ether.h> in the Linux Kernel documentation. Usually, ETH_P_ALL
            (0x0003) is not a good idea.
        mtu (int): sets the maximum transmission unit size for this connection. Defaults
            to 1518 for standard Ethernet.
        has_framecheck (bool): Indicates if the target ethernet protocol needs 4 bytes for a framecheck.
            Default True (for standard Ethernet).
    """

    def __init__(self, interface, send_timeout=5.0, recv_timeout=5.0, ethernet_proto=0, mtu=1518, has_framecheck=True):
        super(RawL2SocketConnection, self).__init__(send_timeout, recv_timeout)

        self.interface = interface
        self.ethernet_proto = ethernet_proto
        self.mtu = mtu
        self.has_framecheck = has_framecheck
        self.max_send_size = mtu
        if self.has_framecheck:
            self.max_send_size -= 4

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        Returns:
            None
        """
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ethernet_proto))
        self._sock.bind((self.interface, self.ethernet_proto))

        super(RawL2SocketConnection, self).open()

    def recv(self, max_bytes):
        """
        Receives a packet from the raw socket. If max_bytes < mtu, only the first max_bytes are returned and
        the rest of the packet is discarded. Otherwise, return the whole packet.

        Args:
            max_bytes (int): Maximum number of bytes to return. 0 to return the whole packet.

        Returns:
            Received data
        """
        if self.ethernet_proto is None:
            raise Exception(
                "Receiving on Raw Layer 2 sockets is only supported if the socket "
                "is bound to an interface and protocol."
            )

        data = b""

        try:
            data = self._sock.recv(self.mtu)

            if 0 < len(data) < max_bytes:
                data = data[:max_bytes]
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
        Data will be trunctated to self.max_send_size (Default: 1514
        bytes).

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

        data = data[: self.max_send_size]

        try:
            num_sent = self._sock.send(data)

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

    @property
    def info(self):
        return "{0}, type 0x{1:04x}".format(self.interface, self.ethernet_proto)
