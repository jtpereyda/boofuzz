.. _connections:

===========
Connections
===========

Connection objects implement :class:`ITargetConnection <boofuzz.connections.ITargetConnection>`.
Available options include:

- :class:`TCPSocketConnection <boofuzz.connections.TCPSocketConnection>`
- :class:`UDPSocketConnection <boofuzz.connections.UDPSocketConnection>`
- :class:`SSLSocketConnection <boofuzz.connections.SSLSocketConnection>`
- :class:`RawL2SocketConnection <boofuzz.connections.RawL2SocketConnection>`
- :class:`RawL3SocketConnection <boofuzz.connections.RawL3SocketConnection>`
- :func:`SocketConnection (depreciated)<boofuzz.connections.SocketConnection>`
- :class:`SerialConnection <boofuzz.connections.SerialConnection>`

ITargetConnection
=================
.. autoclass:: boofuzz.connections.ITargetConnection
    :members:
    :undoc-members:
    :show-inheritance:

BaseSocketConnection
====================
.. autoclass:: boofuzz.connections.BaseSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

TCPSocketConnection
===================
.. autoclass:: boofuzz.connections.TCPSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

UDPSocketConnection
===================
.. autoclass:: boofuzz.connections.UDPSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

SSLSocketConnection
===================
.. autoclass:: boofuzz.connections.SSLSocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

RawL2SocketConnection
=====================
.. autoclass:: boofuzz.connections.RawL2SocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

RawL3SocketConnection
=====================
.. autoclass:: boofuzz.connections.RawL3SocketConnection
    :members:
    :undoc-members:
    :show-inheritance:

SocketConnection
================
.. autofunction:: boofuzz.connections.SocketConnection

SerialConnection
================
.. autoclass:: boofuzz.connections.SerialConnection
    :members:
    :undoc-members:
    :show-inheritance:
