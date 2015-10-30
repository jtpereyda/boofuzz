Checksum Class
==============
Sulley's Checksum class creates a block that calculates the checksum of another
block.

Algorithms
----------
Checksum contains only the Sulley block logic for a checksum, not specific
algorithm implementations.
Algorithms are implemented with a library or a free function.

Callback
--------
Checksum takes advantage of callbacks to ensure that it is calculated _after_
its target block is calculated.
When a Checksum block is rendered, it will append itself to its Request's
callback list.

Recursion
---------
To enable a checksum to be calculated over its parent block, it is necessary
to account for recursion.
This is done with a recursion flag.
When Checksum renders itself for the sake of calculations, it will set a
recursion flag on itself.
Then, when the parent block again renders the Checksum, Checksum will check its
own recursion flag and return its default value.

Notes
-----
The recursion and callback methods were both created with similar goals.
Recursion could make the callback unnecessary, but until no other blocks use
callbacks, neglecting to use it here could result in a checksum over
not-yet-calculated information.

UDP
---
UDP is special in that it is computed over a pseudo-header, including selected
fields from IPv4 and the entire UDP header and payload.
The IPv4 fields are:

 * IPv4 Source Address
 * IPv4 Destination Address
 * Protocol (should always be UDP)
 * Length of UDP header+payload

Original design considered:

 1. Passing a reference to the IPv4 Sulley Block and navigating to its children.
 2. Passing source and destination addresses directly to the Checksum
    constructor.
 3. Passing references to the source and destination Sulley Blocks into the
    Checksum constructor.
    
Option 1 was rejected as being too involved.
It would need to know the structure of the IPv4 Sulley Block, which would
result in complexity and possibly duplicated information.

Option 2 was rejected as inferior to 1 and 3.
With option 2, when the IPv4 source or destination address is being fuzzed,
the UDP checksum will automatically start failing.
This could draw attention away from the IPv4 src/dst fields for the sake of
fuzzing.

With option 3, when the IPv4 src/dst fields are being fuzzed, the UDP checksum
will still pass.
Furthermore, taking a reference to two Sulley Blocks is relatively easy.