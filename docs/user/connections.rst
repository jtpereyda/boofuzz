.. _connections:

===========
Connections
===========

Connection objects implement :class:`ITargetConnection <boofuzz.ITargetConnection>`. Available options include:

- :class:`TCPSocketConnection <boofuzz.TCPSocketConnection>`
- :class:`UDPSocketConnection <boofuzz.UDPSocketConnection>`
- :class:`SSLSocketConnection <boofuzz.SSLSocketConnection>`
- :class:`RawL2SocketConnection <boofuzz.RawL2SocketConnection>`
- :class:`RawL3SocketConnection <boofuzz.RawL3SocketConnection>`
- :meth:`SocketConnection (depreciated)<boofuzz.socket_connection.SocketConnection>`
- :class:`SerialConnection <boofuzz.SerialConnection>`

ITargetConnection
=================
.. autoclass:: boofuzz.ITargetConnection
    :members:
    :undoc-members:
    :show-inheritance:

BaseSocketConnection
====================
.. autoclass:: boofuzz.BaseSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

TCPSocketConnection
===================
.. autoclass:: boofuzz.TCPSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

UDPSocketConnection
===================
.. autoclass:: boofuzz.UDPSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

SSLSocketConnection
===================
.. autoclass:: boofuzz.SSLSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

RawL2SocketConnection
=====================
.. autoclass:: boofuzz.RawL2SocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

RawL3SocketConnection
=====================
.. autoclass:: boofuzz.RawL3SocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

SocketConnection
================
.. automethod:: boofuzz.socket_connection.SocketConnection

SerialConnection
================
.. autoclass:: boofuzz.SerialConnection
    :members:
    :undoc-members:
    :show-inheritance:
