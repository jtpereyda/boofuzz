.. _other-modules:

=============
Other Modules
=============

Test Case Session Reference
===========================
.. autoclass:: boofuzz.ProtocolSessionReference
    :members:
    :undoc-members:
    :show-inheritance:

Test Case Context
=================
.. autoclass:: boofuzz.ProtocolSession
    :members:
    :undoc-members:
    :show-inheritance:

Helpers
=======
.. automodule:: boofuzz.helpers
    :members:
    :undoc-members:
    :show-inheritance:

IP Constants
============
.. automodule:: boofuzz.connections.ip_constants
    :members:
    :undoc-members:
    :show-inheritance:

PED-RPC
=======
Boofuzz provides an RPC primitive to host monitors on remote machines. The main
boofuzz instance acts as a client that connects to (remotely) running RPC
server instances, transparently calling functions that are called on the
instance of the client on the server instance and returning their result as a 
python object. As a general rule, data that's passed over the RPC interface
needs to be able to be pickled.

Note that PED-RPC provides no authentication or authorization in any form. It
is advisable to only run it on trusted networks.

.. automodule:: boofuzz.monitors.pedrpc
    :members:
    :undoc-members:
    :show-inheritance:

DCE-RPC
=======
.. automodule:: boofuzz.utils.dcerpc
    :members:
    :undoc-members:
    :show-inheritance:

Crash binning
=============
.. automodule:: boofuzz.utils.crash_binning
    :members:
    :undoc-members:
    :show-inheritance:

EventHook
=========
.. automodule:: boofuzz.event_hook
    :members:
    :undoc-members:
    :show-inheritance:

