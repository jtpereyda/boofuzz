import socket
import threading
import time
import unittest
# pytest is required as an extras_require:
# noinspection PyPackageRequirements
import mock
from boofuzz import FuzzLogger
from boofuzz import Session
from boofuzz import SocketConnection
from boofuzz import Target
from boofuzz import s_initialize, s_string, s_static, s_get

THREAD_WAIT_TIMEOUT = 10  # Time to wait for a thread before considering it failed.


# TODO Test causes Resource temporarily unavailable error
# TODO use mock instead of the home made mock
# TODO how to share MiniTestServer and THREAD_WAIT_TIMEOUT with test_socket_connection.py


class MiniTestServer(object):
    """
    Small server class for testing SocketConnection.
    """

    def __init__(self, stay_silent=False, proto='tcp', host="0.0.0.0"):
        self.server_socket = None
        self.received = None
        self.data_to_send = bytes("\xFE\xEB\xDA\xED")
        self.active_port = None
        self.stay_silent = stay_silent
        self.proto = proto
        self.host = host
        self.timeout = 5  # Timeout while waiting for the unit test packets.

    def bind(self):
        """
        Bind server, and call listen if using TCP, meaning that the client test code can successfully connect.
        """
        if self.proto == 'tcp':
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.proto == 'udp':
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.proto == 'raw':
            self.server_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        else:
            raise Exception("Invalid protocol type: '{0}'".format(self.proto))

        self.server_socket.bind((self.host, 0))  # let OS choose a free port

        if self.proto == 'tcp':
            self.server_socket.listen(1)

        self.active_port = self.server_socket.getsockname()[1]

    def serve_once(self):
        """
        Serve one connection and send a reply, unless stay_silent is set.
        :return:
        """
        self.server_socket.settimeout(self.timeout)

        if self.proto == 'tcp':
            (client_socket, address) = self.server_socket.accept()

            self.received = client_socket.recv(10000)

            if not self.stay_silent:
                client_socket.send(self.data_to_send)

            client_socket.close()
        elif self.proto == 'udp':
            data, addr = self.server_socket.recvfrom(1024)
            self.received = data
            if not self.stay_silent:
                self.server_socket.sendto(self.data_to_send, addr)
        elif self.proto == 'raw':
            data, addr = self.server_socket.recvfrom(10000)
            self.received = data
            if not self.stay_silent:
                self.server_socket.sendto(self.data_to_send, addr)
        else:
            raise Exception("Invalid protocol type: '{0}'".format(self.proto))

        self.server_socket.close()
        self.server_socket = None
        self.active_port = None

    def receive_until(self, expected):
        """Receive repeatedly until expected is received.

        This is handy for a noisy socket (e.g., layer 2 or layer 3 sockets that
        receive data from multiple applications).

        Will send a reply to first connection, unless stay_silent is set.

        Puts received data in self.received if and only if expected is
        received.

        @param expected: Expected value to look for.
        """
        self.server_socket.settimeout(self.timeout)

        if self.proto == 'raw':
            # Keep receiving
            elapsed_time = 0
            start_time = time.time()
            while elapsed_time < self.timeout:
                self.server_socket.settimeout(self.timeout - elapsed_time)
                try:
                    data, addr = self.server_socket.recvfrom(10000)
                    if data == expected:
                        self.received = data
                        if not self.stay_silent:
                            self.server_socket.sendto(self.data_to_send, addr)
                        break
                except socket.timeout:
                    break
                elapsed_time = time.time() - start_time
        else:
            raise Exception("Invalid protocol type: '{0}'".format(self.proto))

        self.server_socket.close()
        self.server_socket = None
        self.active_port = None


class TestNoResponseFailure(unittest.TestCase):
    def setUp(self):
        #self.mock_logger_1 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        #self.mock_logger_2 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        #self.logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self.mock_logger_1, self.mock_logger_2])

        #self.some_text = "Some test text"
        #self.some_data = bytes('1234567890\0')

        self.restarts = 0

    def _mock_restart_target(self):
        def x(target):
            self.restarts += 1
        return x

    def test_no_response_causes_restart(self):
        """
        Given: A listening server which will give no response
          and: A Session ready to fuzz that server
        When: Calling fuzz_single_case()
        Then: The restart_target method is called.
        """
        # Given
        server = MiniTestServer(host='localhost', stay_silent=True)
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        session = Session(
            target=Target(
                connection=SocketConnection('localhost', server.active_port, proto='tcp'),
            ),
            fuzz_loggers=[],  # log to nothing
            check_data_received_each_request=True,
        )
        session.restart_target = self._mock_restart_target()

        s_initialize("test-msg")
        s_string("test-str-value")
        s_static("\r\n")

        session.connect(s_get("test-msg"))

        # When
        session.fuzz_single_case(1)

        # Then
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        self.assertEqual(1, self.restarts)


if __name__ == '__main__':
    unittest.main()
