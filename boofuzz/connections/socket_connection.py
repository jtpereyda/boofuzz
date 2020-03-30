from __future__ import absolute_import

import warnings

from boofuzz import exception
from boofuzz.connections import (
    raw_l2_socket_connection,
    raw_l3_socket_connection,
    ssl_socket_connection,
    tcp_socket_connection,
    udp_socket_connection,
)

_PROTOCOLS = ["tcp", "ssl", "udp", "raw-l2", "raw-l3"]
_PROTOCOLS_PORT_REQUIRED = ["tcp", "ssl", "udp"]


def SocketConnection(
    host,
    port=None,
    proto="tcp",
    bind=None,
    send_timeout=5.0,
    recv_timeout=5.0,
    ethernet_proto=None,
    l2_dst=b"\xFF" * 6,
    udp_broadcast=False,
    server=False,
    sslcontext=None,
    server_hostname=None,
):
    """ITargetConnection implementation using sockets.

    Supports UDP, TCP, SSL, raw layer 2 and raw layer 3 packets.

    .. note:: SocketConnection is deprecated and will be removed in a future version of Boofuzz.
        Use the classes derived from :class:`BaseSocketConnection <boofuzz.connections.BaseSocketConnection>` instead.

    .. versionchanged:: 0.2.0
        SocketConnection has been moved into the connections subpackage.
        The full path is now boofuzz.connections.socket_connection.SocketConnection

    .. deprecated:: 0.2.0
        Use the classes derived from :class:`BaseSocketConnection <boofuzz.connections.BaseSocketConnection>` instead.

    Examples::

        tcp_connection = SocketConnection(host='127.0.0.1', port=17971)
        udp_connection = SocketConnection(host='127.0.0.1', port=17971, proto='udp')
        udp_connection_2_way = SocketConnection(host='127.0.0.1', port=17971, proto='udp', bind=('127.0.0.1', 17972)
        udp_broadcast = SocketConnection(host='127.0.0.1', port=17971, proto='udp', bind=('127.0.0.1', 17972),
                                         udp_broadcast=True)
        raw_layer_2 = (host='lo', proto='raw-l2')
        raw_layer_2 = (host='lo', proto='raw-l2',
                       l2_dst='\\xFF\\xFF\\xFF\\xFF\\xFF\\xFF', ethernet_proto=socket_connection.ETH_P_IP)
        raw_layer_3 = (host='lo', proto='raw-l3')


    Args:
        host (str): Hostname or IP address of target system, or network interface string if using raw-l2 or raw-l3.
        port (int): Port of target service. Required for proto values 'tcp', 'udp', 'ssl'.
        proto (str): Communication protocol ("tcp", "udp", "ssl", "raw-l2", "raw-l3"). Default "tcp".
            raw-l2: Send packets at layer 2. Must include link layer header (e.g. Ethernet frame).
            raw-l3: Send packets at layer 3. Must include network protocol header (e.g. IPv4).
        bind (tuple (host, port)): Socket bind address and port. Required if using recv() with 'udp' protocol.
        send_timeout (float): Seconds to wait for send before timing out. Default 5.0.
        recv_timeout (float): Seconds to wait for recv before timing out. Default 5.0.
        ethernet_proto (int): Ethernet protocol when using 'raw-l3'. 16 bit integer.
            Default ETH_P_IP (0x0800) when using 'raw-l3'. See "if_ether.h" in Linux documentation for more options.
        l2_dst (str): Layer 2 destination address (e.g. MAC address). Used only by 'raw-l3'.
            Default '\xFF\xFF\xFF\xFF\xFF\xFF' (broadcast).
        udp_broadcast (bool): Set to True to enable UDP broadcast. Must supply appropriate broadcast address for send()
            to work, and '' for bind host for recv() to work.
        server (bool): Set to True to enable server side fuzzing.
        sslcontext (ssl.SSLContext): Python SSL context to be used. Required if server=True or server_hostname=None.
        server_hostname (string): server_hostname, required for verifying identity of remote SSL/TLS server.


    """

    warnings.warn(
        "SocketConnection is deprecated and will be removed in a future version of Boofuzz. "
        "Use the classes derived from BaseSocketConnection instead.",
        FutureWarning,
    )
    if proto not in _PROTOCOLS:
        raise exception.SullyRuntimeError("INVALID PROTOCOL SPECIFIED: %s" % proto)

    if proto in _PROTOCOLS_PORT_REQUIRED and port is None:
        raise ValueError("__init__() argument port required for protocol {0}".format(proto))

    if proto == "udp":
        return udp_socket_connection.UDPSocketConnection(
            host, port, send_timeout, recv_timeout, server, bind, udp_broadcast
        )
    elif proto == "tcp":
        return tcp_socket_connection.TCPSocketConnection(host, port, send_timeout, recv_timeout, server)
    elif proto == "ssl":
        return ssl_socket_connection.SSLSocketConnection(
            host, port, send_timeout, recv_timeout, server, sslcontext, server_hostname
        )
    elif proto == "raw-l2":
        return raw_l2_socket_connection.RawL2SocketConnection(host, send_timeout, recv_timeout)
    elif proto == "raw-l3":
        if ethernet_proto is None:
            ethernet_proto = raw_l3_socket_connection.ETH_P_IP

        return raw_l3_socket_connection.RawL3SocketConnection(host, send_timeout, recv_timeout, ethernet_proto, l2_dst)
