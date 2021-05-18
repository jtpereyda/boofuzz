from __future__ import absolute_import

import errno
import socket
import sys

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection


class IPSocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with IP based protocols.

    .. versionadded:: 0.3.1

    Args:
        target_ip (str): Destination IP address  to send packets to.
        local_ip (str, optional): eIP address of the local interface. Defaults to auto-detect with fallback to 0.0.0.0.
        ip_proto (int, optional): IP protocol to set in the header. Defaults to IPPROTO_RAW. If using IPPROTO_RAW, you
            have to provide a valid IP header, else the OS will reject the packet.
        send_timeout (float, optional): Seconds to wait for recv before timing out. Default 5.0.
        recv_timeout (float, optional): Seconds to wait for recv before timing out. Default 5.0.
        validate_sender_address (bool, optional): When receiving, only return packages where the sender IP address
            matches target_ip. Retry on mismatch. Set to False to receive from any source. Default True.
    """

    def __init__(
        self,
        target_ip,
        local_ip=None,
        ip_proto=socket.IPPROTO_RAW,
        send_timeout=5.0,
        recv_timeout=5.0,
        validate_sender_address=True,
    ):
        super(IPSocketConnection, self).__init__(send_timeout, recv_timeout)

        self._src_ip = local_ip
        self._dst_ip = target_ip
        self._ip_proto = ip_proto

    def open(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, self._ip_proto)
        if self._src_ip is not None:
            self._sock.bind((self._src_ip, 0))
        else:
            local_ip = socket.gethostbyname(socket.gethostname())
            if local_ip.startswith("127.0."):
                local_ip = "0.0.0.0"
            self._sock.bind((local_ip, 0))

        super(IPSocketConnection, self).open()

    def recv(self, max_bytes):
        """
        Receives a packet from the socket. Only packets whose destination IP address equals `local_ip` and whose IP
        protocol equals `ip_proto` are forwarded.
        If max_bytes < packet_size, only the first max_bytes are returned and the rest of the packet is discarded.
        Otherwise, return the whole packet.

        .. note::
            The full IP header is returned in addition to the payload. Keep this in mind when parsing the response.

        Args:
            max_bytes (int): Maximum number of bytes to return.

        Returns:
            bytes: Received IP header + payload
        """
        data = b""
        address = ""

        while address != self._dst_ip:
            try:
                data, address = self._sock.recvfrom(max_bytes)
            except socket.timeout:
                raise_(exception.BoofuzzTargetConnectionTimeout(), None, sys.exc_info()[2])
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
                    raise_(exception.BoofuzzTargetConnectionTimeout(), None, sys.exc_info()[2])
                else:
                    raise

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        .. note::
            If using IPPROTO_RAW you have to include a valid IP header, else the OS will reject the operation.
            For any other protocol, the OS will generate the IP header for you.

        Args:
            data (bytes): Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

        try:
            num_sent = self._sock.sendto(data, (self._dst_ip, 0))
        except socket.timeout:
            raise_(exception.BoofuzzTargetConnectionTimeout(), None, sys.exc_info()[2])
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise_(
                    exception.BoofuzzTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                    None,
                    sys.exc_info()[2],
                )
            elif e.errno in [errno.ECONNRESET, errno.ENETRESET, errno.ETIMEDOUT, errno.EPIPE]:
                raise_(exception.BoofuzzTargetConnectionReset(), None, sys.exc_info()[2])
            elif e.errno in [errno.EINVAL]:
                raise_(
                    exception.BoofuzzError(
                        "Invalid argument in sendto(). Make sure to provide a valid IP header in " "case of IPPROTO_RAW"
                    ),
                    None,
                    sys.exc_info()[2],
                )
            else:
                raise

        return num_sent

    @property
    def info(self):
        return "{0}, IP protocol 0x{1:02x}".format(self._dst_ip, self._ip_proto)
