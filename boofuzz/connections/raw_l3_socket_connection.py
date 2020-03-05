from __future__ import absolute_import

import errno
import socket
import sys

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection

ETH_P_ALL = 0x0003  # Ethernet protocol: Every packet, see Linux if_ether.h docs for more details.
ETH_P_IP = 0x0800  # Ethernet protocol: Internet Protocol packet, see Linux <net/if_ether.h> docs for more details.


class RawL3SocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with Raw Layer 2 Sockets.

    .. versionadded:: 0.2.0

    Args:
        interface (str): Interface to send and receive on.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        ethernet_proto (int): Ethernet protocol to bind to. Defaults to ETH_P_IP (0x0800).
        l2_dst (str): Layer2 destination address (e.g. MAC address). Default '\xFF\xFF\xFF\xFF\xFF\xFF' (broadcast)
        packet_size (int): Maximum packet size (in bytes). Default 1500 if the underlying interface uses
            standard ethernet for layer 2. Otherwise, a different packet size may apply (e.g. Jumboframes,
            802.5 Token Ring, 802.11 wifi, ...) that must be specified.
    """

    def __init__(
        self,
        interface,
        send_timeout=5.0,
        recv_timeout=5.0,
        ethernet_proto=ETH_P_IP,
        l2_dst=b"\xff" * 6,
        packet_size=1500,
    ):
        super(RawL3SocketConnection, self).__init__(send_timeout, recv_timeout)

        self.interface = interface
        self.ethernet_proto = ethernet_proto
        self.l2_dst = l2_dst
        self.packet_size = packet_size

    def open(self):
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(self.ethernet_proto))
        self._sock.bind((self.interface, self.ethernet_proto))

        super(RawL3SocketConnection, self).open()

    def recv(self, max_bytes):
        """
        Receives a packet from the raw socket. If max_bytes < packet_size, only the first max_bytes are returned and
        the rest of the packet is discarded. Otherwise, return the whole packet.

        Args:
            max_bytes (int): Maximum number of bytes to return. 0 to return the whole packet.

        Returns:
            Received data
        """
        data = b""

        try:
            data = self._sock.recv(self.packet_size)

            if 0 < max_bytes < self.packet_size:
                data = data[: self._packet_size]

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
        Data will be trunctated to self.packet_size (Default: 1500
        bytes).

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

        data = data[: self.packet_size]

        try:
            num_sent = self._sock.sendto(data, (self.interface, self.ethernet_proto, 0, 0, self.l2_dst))

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
