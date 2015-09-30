import fcntl
import threading
import unittest
import logging
import struct
import zlib
from sulley.socket_connection import SocketConnection
from sulley import socket_connection
import socket

THREAD_WAIT_TIMEOUT = 10  # Time to wait for a thread before considering it failed.
ETH_P_ALL = 0x0003  # Ethernet protocol: Every packet, see Linux if_ether.h docs for more details.

UDP_HEADER_LEN = 8
IP_HEADER_LEN = 20

ETHER_TYPE_IPV4 = "\x08\x00"  # Ethernet frame EtherType for IPv4
IPV4_PROTOCOL_UDP = "\x11"  # Protocol code for UDP in IPv4 packet


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


def ipv4_checksum(msg):
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


def ip_packet(payload, src_ip, dst_ip, protocol=IPV4_PROTOCOL_UDP):
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

    checksum = struct.pack(">H", ipv4_checksum(ip_header))
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


def get_packed_ip_address(ifname):
    """
    Returns IP address of the ifname interface as 4-byte string.

    :type ifname: str
    :param ifname: Interface whose IP address should be returned.

    :rtype: str
    :return: IP address of ifname.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24]


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
        self.server_socket.settimeout(5)

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


class TestSocketConnection(unittest.TestCase):
    def setUp(self):
        self.local_ip = get_packed_ip_address('eth0')

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
        t.join(THREAD_WAIT_TIMEOUT)
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
        t.join(THREAD_WAIT_TIMEOUT)
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
        server = MiniTestServer(proto='udp')
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
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, server.data_to_send)

    def test_raw_l2(self):
        """
        Given: A SocketConnection 'raw-l2' object.
          and: A raw UDP/IP/Ethernet packet.
          and: A UDP server, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: The server receives data from send().
         And: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imagination does not breed insanity. Exactly what does breed insanity is reason.'
                             ' Poets do not go mad; but chess-players do. Mathematicians go mad, and cashiers;'
                             ' but creative artists very seldom. "')

        # Given
        server = MiniTestServer(proto='udp')
        server.data_to_send = "GKC"
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host="eth0", port=0, proto='raw-l2')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = ethernet_frame(
            payload=ip_packet(
                payload=udp_packet(
                    payload=data_to_send,
                    src_port=server.active_port + 1,
                    dst_port=server.active_port),
                src_ip=self.local_ip[0:3] + "\x00",
                dst_ip=self.local_ip),
            src_mac="\x00" * 6,
            dst_mac="\xff" * 6)

        # When
        uut.open()
        uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, bytes(''))

    def test_raw_l3(self):
        """
        Given: A SocketConnection 'raw-l3' object.
          and: A raw UDP/IP packet.
          and: A UDP server, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: The server receives data from send().
         And: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imprudent marriages!" roared Michael. "And pray where in earth or heaven are there any'
                             ' prudent marriages?""')

        # Given
        server = MiniTestServer(proto='udp')
        server.data_to_send = "GKC"
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host="eth0", port=socket_connection.ETH_P_IP, proto='raw-l3')
        uut.logger = logging.getLogger("SulleyUTLogger")

        raw_packet = ip_packet(
            payload=udp_packet(
                payload=data_to_send,
                src_port=server.active_port + 1,
                dst_port=server.active_port),
            src_ip=self.local_ip[0:3] + "\x00",
            dst_ip=self.local_ip)

        # When
        uut.open()
        uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(data_to_send, server.received)
        self.assertEqual(received, bytes(''))

    def test_raw_l2_loopback(self):
        """
        Test 'raw' protocol with the loopback interface 'lo'.
        So far this has only worked if the server is also using a raw socket.

        Given: A SocketConnection 'raw-l2' object.
          and: A raw UDP/IP/Ethernet packet.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: The server receives the raw packet data from send().
         And: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imagination does not breed insanity. Exactly what does breed insanity is reason.'
                             ' Poets do not go mad; but chess-players do. Mathematicians go mad, and cashiers;'
                             ' but creative artists very seldom. "')

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host="lo", port=socket_connection.ETH_P_IP, proto='raw-l2')
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

        # When
        uut.open()
        uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual(raw_packet, server.received)
        self.assertEqual(received, bytes(''))

    def test_raw_l3_loopback(self):
        """
        Test 'raw' protocol with the loopback interface 'lo'.
        So far this has only worked if the server is also using a raw socket. This is a notable shortcoming, either
        of the loopback interface or of SocketConnection's implementation.

        Given: A SocketConnection 'raw-l3' object.
          and: A raw UDP/IP packet.
          and: A server socket created with AF_PACKET, SOCK_RAW, configured to respond.
        When: Calling SocketConnection.open(), .send() with the valid UDP packet, .recv(), and .close()
        Then: The server receives the raw packet data from send(), with an Ethernet header appended.
         And: SocketConnection.recv() returns bytes('').
        """
        data_to_send = bytes('"Imprudent marriages!" roared Michael. "And pray where in earth or heaven are there any'
                             ' prudent marriages?""')

        # Given
        server = MiniTestServer(proto='raw', host='lo')
        server.data_to_send = "GKC"
        server.bind()

        t = threading.Thread(target=server.serve_once)
        t.daemon = True
        t.start()

        uut = SocketConnection(host="lo", port=socket_connection.ETH_P_IP, proto='raw-l3')
        uut.logger = logging.getLogger("SulleyUTLogger")

        # Assemble packet...
        raw_packet = ip_packet(
            payload=udp_packet(
                payload=data_to_send,
                src_port=server.active_port + 1,
                dst_port=server.active_port),
            src_ip="\x7F\x00\x00\x01",
            dst_ip="\x7F\x00\x00\x01")

        # When
        uut.open()
        uut.send(data=raw_packet)
        received = uut.recv(10000)
        uut.close()

        # Wait for the other thread to terminate
        t.join(THREAD_WAIT_TIMEOUT)
        self.assertFalse(t.isAlive())

        # Then
        self.assertEqual('\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + raw_packet, server.received)
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
        with self.assertRaises(Exception):
            SocketConnection(port=5)
        with self.assertRaises(Exception):
            SocketConnection(port=5, proto='tcp')
        with self.assertRaises(Exception):
            SocketConnection(port=5, proto='udp')
        with self.assertRaises(Exception):
            SocketConnection(port=5, proto='ssl')
        with self.assertRaises(Exception):
            SocketConnection(port=5, proto='raw-l2')
        with self.assertRaises(Exception):
            SocketConnection(port=5, proto='raw-l3')


if __name__ == '__main__':
    unittest.main()
