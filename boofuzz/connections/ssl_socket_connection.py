from __future__ import absolute_import

import ssl

from future.utils import raise_

from boofuzz import exception
from boofuzz.connections import tcp_socket_connection


class SSLSocketConnection(tcp_socket_connection.TCPSocketConnection):
    """BaseSocketConnection implementation for use with SSL Sockets.

    .. versionadded:: 0.2.0

    Args:
        host (str): Hostname or IP adress of target system.
        port (int): Port of target service.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        server (bool): Set to True to enable server side fuzzing.
        sslcontext (ssl.SSLContext): Python SSL context to be used. Required if server=True or server_hostname=None.
        server_hostname (string): server_hostname, required for verifying identity of remote SSL/TLS server
    """

    def __init__(
        self, host, port, send_timeout=5.0, recv_timeout=5.0, server=False, sslcontext=None, server_hostname=None
    ):
        super(SSLSocketConnection, self).__init__(host, port, send_timeout, recv_timeout, server)

        self.sslcontext = sslcontext
        self.server_hostname = server_hostname

        if self.server is True and self.sslcontext is None:
            raise ValueError("Parameter sslcontext is required when server=True.")
        if self.sslcontext is None and self.server_hostname is None:
            raise ValueError("SSL/TLS requires either sslcontext or server_hostname to be set.")

    def open(self):
        # If boofuzz is the SSL client and user did not give us a SSLContext,
        # then we just use a default one.
        if self.server is False and self.sslcontext is None:
            self.sslcontext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.sslcontext.check_hostname = True
            self.sslcontext.verify_mode = ssl.CERT_REQUIRED

        super(SSLSocketConnection, self)._open_socket()

        # Create SSL socket
        try:
            self._sock = self.sslcontext.wrap_socket(
                self._sock, server_side=self.server, server_hostname=self.server_hostname
            )
        except ssl.SSLError as e:
            self.close()
            raise exception.BoofuzzTargetConnectionFailedError(str(e))
        except AttributeError:
            # No SSL context set
            pass

        super(SSLSocketConnection, self)._connect_socket()

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        data = b""

        try:
            data = super(SSLSocketConnection, self).recv(max_bytes)
        except ssl.SSLError as e:
            # If an SSL error is thrown the connection should be treated as lost
            # All other exceptions should be handled / raised / re-raised by the parent class.
            raise_(exception.BoofuzzSSLError(str(e)))

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

        if len(data) > 0:
            try:
                num_sent = super(SSLSocketConnection, self).send(data)
            except ssl.SSLError as e:
                # If an SSL error is thrown the connection should be treated as lost.
                # All other exceptions should be handled / raised / re-raised by the parent class.
                raise_(exception.BoofuzzSSLError(str(e)))

        return num_sent
