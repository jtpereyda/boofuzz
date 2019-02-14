import functools
import threading
import time
import logging
import socket
import struct
import sys
import unittest
import zlib

import pytest
import ipaddress
import netifaces

from boofuzz.socket_connection import SocketConnection
from boofuzz import socket_connection
from boofuzz import ip_constants
from boofuzz import helpers

THREAD_WAIT_TIMEOUT = 10  # Time to wait for a thread before considering it failed.
ETH_P_ALL = 0x0003  # Ethernet protocol: Every packet, see Linux if_ether.h docs for more details.

UDP_HEADER_LEN = 8
IP_HEADER_LEN = 20

ETHER_TYPE_IPV4 = struct.pack(">H", socket_connection.ETH_P_IP)  # Ethernet frame EtherType for IPv4

RAW_L2_MAX_PAYLOAD = socket_connection.SocketConnection.MAX_PAYLOADS['raw-l2']
RAW_L3_MAX_PAYLOAD = socket_connection.SocketConnection.MAX_PAYLOADS['raw-l3']

TEST_ERR_NO_NON_LOOPBACK_IPV4 = 'No local non-loopback IPv4 address found.'


def bytes_or_unicode_to_unicode(s):
    if isinstance(s, bytes):
        return s.decode('utf-8')
    else:
        return s


def get_local_non_loopback_ipv4_addresses_info():
    for interface in netifaces.interfaces():
        # Not all interfaces have an IPv4 address:
        if netifaces.AF_INET in netifaces.ifaddresses(interface):
            # Some interfaces have multiple IPv4 addresses:
            for address_info in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                # netifaces gives unicode strings in Windows, byte strings in Linux:
                address_str = bytes_or_unicode_to_unicode(address_info['addr'])
                if not ipaddress.IPv4Address(address_str).is_loopback:
                    yield address_info


def udp_packet(payload, src_port, dst_port):
    """
    Create a UDP packet.

    :param payload: Payload / next layer protocol.
    :type payload: str

    :param src_port: 16-bit source port number.
    :type src_port: int

    :param dst_port: 16-bit destination port number.
    :type dst_port: int

    :return: UDP packet.
    :rtype: str
    """
    udp_header = struct.pack(">H", src_port)  # Src port
    udp_header += struct.pack(">H", dst_port)  # Dst port
    udp_header += struct.pack(">H", len(payload) + UDP_HEADER_LEN)  # Length
    udp_header += "\x00\x00"  # Checksum (0 means no checksum)
    return udp_header + payload


def ones_complement_sum_carry_16(a, b):
    """
    Compute ones complement and carry at 16 bits.
    :type a: int
    :type b: int
    :return: Sum of a and b, ones complement, carry at 16 bits.
    """
    c = a + b
    return (c & 0xffff) + (c >> 16)


def ip_packet(payload, src_ip, dst_ip, protocol=chr(ip_constants.IPV4_PROTOCOL_UDP)):
    """
    Create an IPv4 packet.

    :type payload: str
    :param payload: Contents of next layer up.

    :type src_ip: str
    :param src_ip: 4-byte source IP address.

    :type dst_ip: str
    :param dst_ip: 4-byte destination IP address.

    :type protocol: str
    :param protocol: Single-byte string identifying next layer's protocol. Default "\x11" UDP.

    :return: IPv4 packet.
    :rtype: str
    """
    ip_header = "\x45"  # Version | Header Length
    ip_header += "\x00"  # "Differentiated Services Field"
    ip_header += struct.pack(">H", IP_HEADER_LEN + len(payload))  # Length
    ip_header += "\x00\x01"  # ID Field
    ip_header += "\x40\x00"  # Flags, Fragment Offset
    ip_header += "\x40"  # Time to live
    ip_header += protocol
    ip_header += "\x00\x00"  # Header checksum (fill in zeros in order to compute checksum)
    ip_header += src_ip
    ip_header += dst_ip

    checksum = struct.pack(">H", helpers.ipv4_checksum(ip_header))
    ip_header = ip_header[:10] + checksum + ip_header[12:]

    return ip_header + payload


def ethernet_frame(payload, src_mac, dst_mac, ether_type=ETHER_TYPE_IPV4):
    """
    Create an Ethernet frame.

    :param payload: Network layer content.
    :type payload: str

    :param src_mac: 6-byte source MAC address.
    :type src_mac: str

    :param dst_mac: 6-byte destination MAC address.
    :type dst_mac: str

    :param ether_type: EtherType indicating protocol of next layer; default "\x08\x00" IPv4.
    :type ether_type: str

    :return: Ethernet frame
    :rtype: str
    """
    eth_header = dst_mac
    eth_header += src_mac
    eth_header += ether_type
    raw_packet = eth_header + payload
    # Ethernet frame check sequence
    crc = zlib.crc32(raw_packet) & 0xFFFFFFFF
    raw_packet += struct.pack("<I", crc)
    return raw_packet


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


class TestSocketConnection(unittest.TestCase):
    """
    Tests only use loopback interface 'lo', since other interfaces would be
    hardware or network dependent.
    """

    def test_tcp_client(self):
        """
        Given: A SocketConnection 'tcp' object and a TCP server.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: send() returns RAW_L3_MAX_PAYLOAD.
         and: Sent and received data is as expected.
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
        send_result = uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(data_to_send))
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    def test_tcp_client_timeout(self):
        """
        Given: A SocketConnection 'tcp' object and a TCP server, set not to respond.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: send() returns length of payload.
         and: Sent works as expected, and recv() returns bytes('') after timing out.
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
        send_result = uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(data_to_send))
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, bytes(''))

    def test_udp_client(self):
        """
        Given: A SocketConnection 'udp' object and a UDP server.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: send() returns length of payload.
         and: Sent and received data is as expected.
        """
        data_to_send = bytes('"Rum idea this is, that tidiness is a timid, quiet sort of thing;'
                             ' why, tidiness is a toil for giants."')

        # Given
        server = MiniTestServer(proto='udp')
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host=socket.gethostname(), port=server.active_port, proto='udp',
                               bind=(socket.gethostname(), 0))
        uut.logger = logging.getLogger("SulleyUTLogger")

        # When
        uut.open()
        send_result = uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(data_to_send))
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    @pytest.mark.skipif(not any(True for _ in get_local_non_loopback_ipv4_addresses_info()),
                        reason=TEST_ERR_NO_NON_LOOPBACK_IPV4)
    def test_udp_broadcast_client(self):
        """
        Given: A SocketConnection 'udp' object with udp_broadcast set, and a UDP server.
        When: Calling SocketConnection.open(), .send(), .recv(), and .close()
        Then: send() returns length of payload.
         and: Sent and received data is as expected.
        """
        try:
            broadcast_addr = get_local_non_loopback_ipv4_addresses_info().next()['broadcast']
        except StopIteration:
            assert False, TEST_ERR_NO_NON_LOOPBACK_IPV4

        data_to_send = bytes('"Never drink because you need it, for this is rational drinking, and the way to death and'
                             ' hell. But drink because you do not need it, for this is irrational drinking, and the'
                             ' ancient health of the world."')

        # Given
        server = MiniTestServer(proto='udp', host='')
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host=broadcast_addr, port=server.active_port, proto='udp',
                               bind=('', server.active_port + 1), udp_broadcast=True)
        uut.logger = logging.getLogger("BoofuzzUTLogger")

        # When
        uut.open()
        send_result = uut.send(data=data_to_send)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(data_to_send))
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l2(self):
        """
        Test 'raw' protocol with the loopback interface 'lo'.

        Given: A SocketConnection 'raw-l2' object.
          and: A raw UDP/IP/Ethernet packet.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns length of payload.
         and: The server receives the raw packet data from send().
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imagination does not breed insanity. Exactly what does breed insanity is reason.'
                             ' Poets do not go mad; but chess-players do. Mathematicians go mad, and cashiers;'
                             ' but creative artists very seldom. "')

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l2')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = ethernet_frame(
                payload=ip_packet(
                        payload=udp_packet(
                                payload=data_to_send,
                                src_port=server.active_port + 1,
                                dst_port=server.active_port),
                        src_ip="\x7F\x00\x00\x01",
                        dst_ip="\x7F\x00\x00\x01"),
                src_mac="\x00" * 6,
                dst_mac="\xff" * 6)
        expected_server_receive = raw_packet

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(expected_server_receive))
        self.assertEqual(raw_packet, server.received)
        self.assertEqual(received, bytes(''))

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l2_max_size(self):
        """
        Test 'raw-l2' max packet size.

        Given: A SocketConnection 'raw-l2' object.
          and: A raw UDP/IP/Ethernet packet of RAW_L2_MAX_PAYLOAD bytes.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns RAW_L2_MAX_PAYLOAD.
         and: The server receives the raw packet data from send().
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('1' * RAW_L2_MAX_PAYLOAD)

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l2')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = data_to_send
        expected_server_receive = raw_packet

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, RAW_L2_MAX_PAYLOAD)
        self.assertEqual(expected_server_receive, server.received)
        self.assertEqual(received, bytes(''))

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l2_oversized(self):
        """
        Test 'raw-l2' oversized packet handling.

        Given: A SocketConnection 'raw-l2' object.
          and: A raw UDP/IP/Ethernet packet of RAW_L2_MAX_PAYLOAD + 1 bytes.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns RAW_L2_MAX_PAYLOAD.
         and: The server receives the first RAW_L2_MAX_PAYLOAD bytes of raw packet data from send().
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('F' * (RAW_L2_MAX_PAYLOAD + 1))

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l2')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = data_to_send
        expected_server_receive = raw_packet[:RAW_L2_MAX_PAYLOAD]

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, RAW_L2_MAX_PAYLOAD)
        self.assertEqual(expected_server_receive, server.received)
        self.assertEqual(received, bytes(''))

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l3(self):
        """
        Test 'raw' protocol with the loopback interface 'lo'.

        Given: A SocketConnection 'raw-l3' object.
          and: A raw UDP/IP packet.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns length of payload.
         and: The server receives the raw packet data from send(), with an Ethernet header appended.
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imprudent marriages!" roared Michael. "And pray where in earth or heaven are there any'
                             ' prudent marriages?""')

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l3')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = ip_packet(
                payload=udp_packet(
                        payload=data_to_send,
                        src_port=server.active_port + 1,
                        dst_port=server.active_port),
                src_ip="\x7F\x00\x00\x01",
                dst_ip="\x7F\x00\x00\x01")
        expected_server_receive = '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + raw_packet

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, len(raw_packet))
        self.assertEqual(expected_server_receive, server.received)
        self.assertEqual(received, bytes(''))

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l3_max_size(self):
        """
        Test 'raw-l3' max packet size.

        Given: A SocketConnection 'raw-l3' object.
          and: A raw UDP/IP packet of RAW_L3_MAX_PAYLOAD bytes.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns RAW_L3_MAX_PAYLOAD bytes.
         and: The server receives the raw packet data from send(), with an Ethernet header appended.
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('0' * RAW_L3_MAX_PAYLOAD)

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l3')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = data_to_send
        expected_server_receive = '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + raw_packet

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, RAW_L3_MAX_PAYLOAD)
        self.assertEqual(expected_server_receive, server.received)
        self.assertEqual(received, bytes(''))

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="Raw sockets not supported on Windows.")
    def test_raw_l3_oversized(self):
        """
        Test 'raw-l3' max packet size.

        Given: A SocketConnection 'raw-l3' object.
          and: A raw UDP/IP packet of RAW_L3_MAX_PAYLOAD + 1 bytes.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: send() returns RAW_L3_MAX_PAYLOAD.
         and: The server receives the raw packet data from send(), with an Ethernet header appended.
         and: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('D' * (RAW_L3_MAX_PAYLOAD + 1))

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        uut = SocketConnection(host="lo", proto='raw-l3')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = data_to_send
        expected_server_receive = '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + raw_packet[
                                                                                               :RAW_L3_MAX_PAYLOAD]

        t = threading.Thread(target=functools.partial(server.receive_until, expected_server_receive))
        t.daemon = True
        t.start()

        # When
        uut.open()
        send_result = uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(send_result, RAW_L3_MAX_PAYLOAD)
        self.assertEqual(expected_server_receive,
                         server.received)
        self.assertEqual(received, bytes(''))

    def test_required_args_port(self):
        """
        Given: No preconditions.
        When: Constructing SocketConnections with:
              protocol types in [default, 'udp', 'tcp', 'ssl'] and
              no port argument.
        Then: Constructor raises exception.
        """
        with self.assertRaises(Exception):
            SocketConnection(host='127.0.0.1')
        with self.assertRaises(Exception):
            SocketConnection(host='127.0.0.1', proto='tcp')
        with self.assertRaises(Exception):
            SocketConnection(host='127.0.0.1', proto='udp')
        with self.assertRaises(Exception):
            SocketConnection(host='127.0.0.1', proto='ssl')

    def test_optional_args_port(self):
        """
        Given: No preconditions.
        When: Constructing SocketConnections with:
              protocol types in ['raw-l2', 'raw-l3'] and
              no port argument.
        Then: Constructor raises no exception.
        """
        SocketConnection(host='127.0.0.1', proto='raw-l2')
        SocketConnection(host='127.0.0.1', proto='raw-l3')

    def test_required_args_host(self):
        """
        Given: No preconditions.
        When: Constructing SocketConnections with:
              protocol types in [default, 'udp', 'tcp', 'ssl', 'raw-l2', 'raw-l3] and
              no host argument.
        Then: Constructor raises exception.
        """
        # This method tests bad argument lists. Therefore we ignore
        # PyArgumentList inspections.
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5)
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5, proto='tcp')
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5, proto='udp')
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5, proto='ssl')
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5, proto='raw-l2')
        with self.assertRaises(Exception):
            # noinspection PyArgumentList
            SocketConnection(port=5, proto='raw-l3')


if __name__ == '__main__':
    unittest.main()
