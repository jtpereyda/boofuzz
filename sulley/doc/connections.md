ITargetConnection
=================
ITargetConnection defines the interface used by the Target classes when sending
and receiving data. This represents the network layer or medium directly below
the protocol under test.

Design Considerations
---------------------
Design goals:

 1. Flexibility with mediums.
 2. Low-layer; avoid interactions with rest of framework.
    * Normal logging is left to higher layers.
 3. Facilitate thorough, auditable logs.
    * The send method returns the number of bytes actually transmitted, since
      some mediums have maximum transmission unit (MTU) limits. The Sulley code
      using a connection should check this value and log the number of bytes
      transmitted; this enables thorough auditability of data actually sent.
