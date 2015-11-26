SocketConnection Class
======================
The SocketConnection is used by the Target class to encapsulate socket
connection details. It implements ITargetConnection.

Multiple protocols may be used; see constructor.

Future
------
The low-level socket protocols have maximum transmission unit (MTU) limits
based on the standard ethernet frame. Availability of jumbo frames could
enable some interesting tests.