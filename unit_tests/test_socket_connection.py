import threading
import unittest
import logging
import struct
import zlib
import itertools
from sulley.socket_connection import SocketConnection
import socket


THREAD_ERROR_TIMEOUT = 10  # Time to wait for a thread before considering it failed.


class MiniTestServer(object):
    def __init__(self, stay_silent=False, use_udp=False, host="0.0.0.0"):
        self.server_socket = None
        self.received = None
        self.data_to_send = bytes("\xFE\xEB\xDA\xED")
        self.active_port = None
        self.stay_silent = stay_silent
        self.use_udp = use_udp
        self.host = host

    def bind(self):
        if not self.use_udp:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.server_socket.bind((self.host, 0))  # let OS choose a free port
        self.active_port = self.server_socket.getsockname()[1]
        return self.active_port

    def serve_once(self):
        if not self.use_udp:
            # Set up server
            self.server_socket.settimeout(5)
            self.server_socket.listen(1)
            (client_socket, address) = self.server_socket.accept()

            # Handle connection
            client_socket.settimeout(1)  # timeout after 1s to keep tests from hanging
            self.received = client_socket.recv(10000)
            if not self.stay_silent:
                client_socket.send(self.data_to_send)
            client_socket.close()
        else:
            self.server_socket.settimeout(5)  # timeout after 1s to keep tests from hanging
            data, addr = self.server_socket.recvfrom(1024)
            self.received = data
            self.server_socket.sendto(self.data_to_send, addr)

        self.server_socket.close()
        self.server_socket = None
        self.active_port = None


class TestSocketConnection(unittest.TestCase):
    def setUp(self):
        pass

    def test_tcp_client(self):
        """
        Given: A SocketConnection 'tcp' object and a TCP server.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: Sent and received data is as expected.
        """
        data_to_send = bytes('uuddlrlrba')

        # Given
        server = MiniTestServer()
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host=socket.gethostname(), port=server.active_port, proto='tcp')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # When
        uut.open()
        uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_ERROR_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    def test_tcp_client_timeout(self):
        """
        Given: A SocketConnection 'tcp' object and a TCP server, set not to respond.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: Sent works as expected, and recv() returns bytes('') after timing out.
        """
        data_to_send = bytes('uuddlrlrba')

        # Given
        server = MiniTestServer(stay_silent=True)
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host=socket.gethostname(), port=server.active_port, proto='tcp')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # When
        uut.open()
        uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_ERROR_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, bytes(''))

    def test_udp_client(self):
        """
        Given: A SocketConnection 'udp' object and a UDP server.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: Sent and received data is as expected.
        """
        data_to_send = bytes('"Rum idea this is, that tidiness is a timid, quiet sort of thing;'
                             ' why, tidiness is a toil for giants."')

        # Given
        server = MiniTestServer(use_udp=True)
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host=socket.gethostname(), port=server.active_port, proto='udp')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # When
        uut.open()
        uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_ERROR_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    def test_raw(self):
        """
        Given: A SocketConnection 'raw' object.
          and: A raw UDP packet.
          and: A UDP server, configured to respond.
        When: Calling SocketConnection.open(), .send() with a valid UDP packet, .recv(), and .close()
        Then: The server receives data from send().
         And: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imagination does not breed insanity. Exactly what does breed insanity is reason.'
                             'Poets do not go mad; but chess-players do. Mathematicians go mad, and cashiers;'
                             'but creative artists very seldom. "')
        udp_header_len = 8
        ip_header_len = 20

        # Given
        server = MiniTestServer(use_udp=True)
        server.data_to_send = "GKC"
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host="eth0", port=0, proto='raw')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        eth_header = "\xff" * 6  # Dst address: Broadcast
        eth_header += "\x00" * 6  # Src address
        eth_header += "\x08\x00"  # Type: IP

        ip_header = "\x45"  # Version | Header Length
        ip_header += "\x00"  # "Differentiated Services Field"
        ip_header += struct.pack(">H", ip_header_len + udp_header_len + len(data_to_send))  # Length
        ip_header += "\x00\x01"  # ID Field
        ip_header += "\x40\x00"  # Flags, Fragment Offset
        ip_header += "\x40"  # Time to live
        ip_header += "\x11"  # Protocol: UDP
        ip_header += "\x00\x00"  # Header checksum
        ip_header += "\xac\x10\x03\x7d"  # Src IP address
        ip_header += "\xac\x10\x03\x7e"  # Dst IP address

        # IPv4 Checksum
        def ones_complement_sum_carry_16(a, b):
            """
            Compute ones complement and carry at 16 bits.
            :type a: int
            :type b: int
            :return: Sum of a and b, ones complement, carry at 16 bits.
            """
            c = a + b
            return (c & 0xffff) + (c >> 16)

        def checksum(msg):
            """
            Return IPv4 checksum of msg.
            :param msg: Message to compute checksum over.
            :return: IPv4 checksum of msg.
            """
            # Pad with 0 byte if needed
            if len(msg) % 2 == 1:
                msg += "\x00"

            collate_bytes = lambda msb, lsb: (ord(msb) << 8) + ord(lsb)
            msg_words = map(collate_bytes, msg[0::2], msg[1::2])
            total = reduce(ones_complement_sum_carry_16, msg_words, 0)
            return ~total & 0xffff

        checksum = struct.pack(">H", checksum(ip_header))
        ip_header = ip_header[:10] + checksum + ip_header[12:]

        # UDP
        udp_header = struct.pack(">H", server.active_port + 1)  # Src port
        udp_header += struct.pack(">H", server.active_port)  # Dst port
        udp_header += struct.pack(">H", len(data_to_send) + udp_header_len)  # Length
        udp_header += "\x00\x00"  # Checksum (0 means no checksum)

        raw_packet = eth_header + ip_header + udp_header + data_to_send

        # Ethernet frame check sequence
        crc = zlib.crc32(raw_packet) & 0xFFFFFFFF

        raw_packet += struct.pack("<I", crc)

        # When
        uut.open()
        uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_ERROR_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, bytes(''))


if __name__ == '__main__':
    unittest.main()
