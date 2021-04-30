from __future__ import absolute_import

import errno
import socket
import sys

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import base_socket_connection


class TCPSocketConnection(base_socket_connection.BaseSocketConnection):
    """BaseSocketConnection implementation for use with TCP Sockets.

    .. versionadded:: 0.2.0

    Args:
        host (str): Hostname or IP adress of target system.
        port (int): Port of target service.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        server (bool): Set to True to enable server side fuzzing.
        graceful_shutdown (bool): close() method attempts a graceful shutdown. Default: True.

    """

    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, server=False, graceful_shutdown=True):
        super(TCPSocketConnection, self).__init__(send_timeout, recv_timeout)

        self.host = host
        self.port = port
        self.server = server
        self._serverSock = None
        self.graceful_shutdown = graceful_shutdown

    def close(self):
        if self.graceful_shutdown:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
                while len(self._sock.recv(1024)) > 0:
                    pass
            except ConnectionError:
                pass
            except OSError as e:
                if e.errno == errno.ENOTCONN:
                    pass
                else:
                    raise
        super(TCPSocketConnection, self).close()

        if self.server:
            self._serverSock.close()

    def open(self):
        self._open_socket()
        self._connect_socket()

    def _open_socket(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # call superclass to set timeout sockopt
        super(TCPSocketConnection, self).open()

    def _connect_socket(self):
        if self.server:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self._sock.bind((self.host, self.port))
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    raise exception.BoofuzzOutOfAvailableSockets()
                else:
                    raise

            self._serverSock = self._sock
            try:
                self._serverSock.listen(1)
                self._sock, addr = self._serverSock.accept()
            except socket.error as e:
                # When connection timeout expires, tear down the server socket so we can re-open it again after
                # restarting the target.
                self.close()
                if e.errno in [errno.EAGAIN]:
                    raise exception.BoofuzzTargetConnectionFailedError(str(e))
                else:
                    raise
        else:
            try:
                self._sock.connect((self.host, self.port))
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    raise exception.BoofuzzOutOfAvailableSockets()
                elif e.errno in [errno.ECONNREFUSED, errno.EINPROGRESS, errno.ETIMEDOUT]:
                    raise exception.BoofuzzTargetConnectionFailedError(str(e))
                else:
                    raise

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target. Timeout results in 0 bytes returned.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data (empty bytes array if timed out).

        Raises:
            BoofuzzTargetConnectionShutdown: Target shutdown connection (e.g. socket recv returns 0 bytes)
            BoofuzzTargetConnectionAborted: ECONNABORTED
            BoofuzzTargetConnectionReset: ECONNRESET, ENETRESET, ETIMEDOUT
        """
        data = b""

        try:
            data = self._sock.recv(max_bytes)
            if len(data) == 0:
                raise exception.BoofuzzTargetConnectionShutdown()
        except socket.timeout:
            data = b""
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise_(
                    exception.BoofuzzTargetConnectionAborted(socket_errno=e.errno, socket_errmsg=e.strerror),
                    None,
                    sys.exc_info()[2],
                )
            elif (e.errno == errno.ECONNRESET) or (e.errno == errno.ENETRESET) or (e.errno == errno.ETIMEDOUT):
                raise_(exception.BoofuzzTargetConnectionReset(), None, sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                data = b""
            else:
                raise

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0

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
        return "{0}:{1}".format(self.host, self.port)
