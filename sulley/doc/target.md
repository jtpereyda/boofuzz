Targets
=======
The Target class defines the interface for Sulley targets, and doubles as
a Socket implementation of the Target interface.

Target Interface
----------------
Sulley uses the Target interface to send and receive data. The Target
implementation(s) should handle logging. This enables consistent send/receive
logging within and between tests.

Target Class
------------
The Target class is also the Socket Target implementation, which the user's
Sulley scripts use to define the target under test.

The user passes host, port, etc. to Target, which passes them to its aggregate
connection object.

Future
------
Having the interface and a specific implementation in one doesn't match up with
our current design strategy, and is a historical holdover. Furthermore, the
socket arguments and argument docstrings are duplicated in Target; Target
receives them and passes them to its aggregate class. One redesign plan is:

 * Remove SerialTarget; have Target take an ITargetConnection in its constructor.
 * This brings us down to a single Target class which doesn't reproduce its
   connection's implementation details (like constructor arguments).
 * The user would now create a Target Connection instead of a Target.
