import itarget_connection
import socket
import ssl
import httplib

import sex
from helpers import get_max_udp_size


class SocketConnection(itarget_connection.ITargetConnection):
    """
    ITargetConnection implementation using sockets. Supports UDP, TCP, SSL.
    """
    def __init__(self, host, port, proto="tcp", bind=None, timeout=5.0):
        """
        @type  host: str
        @param host: Hostname or IP address of target system
        @type  port: int
        @param port: Port of target service
        @type  proto:              str
        @kwarg proto:              (Optional, def="tcp") Communication protocol ("tcp", "udp", "ssl")
        @type  bind:               tuple (host, port)
        @kwarg bind:               (Optional, def=random) Socket bind address and port
        @type  timeout:            float
        @kwarg timeout:            (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        """
        self.max_udp = get_max_udp_size()

        self.host = host
        self.port = port
        self.bind = bind
        self.ssl = False
        self.timeout = timeout
        self.proto = proto.lower()
        self._sock = None
        self.logger = None

        if self.proto == "tcp":
            self.proto = socket.SOCK_STREAM

        elif self.proto == "ssl":
            self.proto = socket.SOCK_STREAM
            self.ssl = True

        elif self.proto == "udp":
            self.proto = socket.SOCK_DGRAM

        else:
            raise sex.SullyRuntimeError("INVALID PROTOCOL SPECIFIED: %s" % self.proto)

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._sock.close()

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._sock = socket.socket(socket.AF_INET, self.proto)

        if self.bind:
            self._sock.bind(self.bind)

        self._sock.settimeout(self.timeout)

        # Connect is needed only for TCP stream
        if self.proto == socket.SOCK_STREAM:
            self._sock.connect((self.host, self.port))

        # if SSL is requested, then enable it.
        if self.ssl:
            ssl_sock = ssl.wrap_socket(self._sock)
            self._sock = httplib.FakeSocket(self._sock, ssl_sock)

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data.
        """
        try:
            return self._sock.recv(max_bytes)
        except socket.timeout:
            return bytes('')

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        :param data: Data to send.

        :return: None
        """
        # TCP/SSL
        if self.proto == socket.SOCK_STREAM:
            self._sock.send(data)
        # UDP
        elif self.proto == socket.SOCK_DGRAM:
            # TODO: this logic does not prevent duplicate test cases, need to address this in the future.
            # If our data is over the max UDP size for this platform, truncate before sending
            if len(data) > self.max_udp:
                self.logger.debug("Too much data for UDP, truncating to %d bytes" % self.max_udp)
                data = data[:self.max_udp]

            self._sock.sendto(data, (self.host, self.port))

        self.logger.debug("Packet sent : " + repr(data))

    def set_logger(self, logger):
        """
        Set this object's (and it's aggregated classes') logger.

        :param logger: Logger to use.
        :type logger: logging.Logger

        :return: None
        """
        self.logger = logger
