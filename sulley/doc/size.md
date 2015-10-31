Size Class
==========
The Size class creates a block that calculates the size of another block.

Calculation
-----------
To calculate the size of its target block, Size simply calls `len()` on the
target (all Sulley Primitives must support `__len__()`).

Design Considerations
---------------------
Size was originally calculated by rendering the target block, or using
callbacks to wait for it to get rendered.
This resulted in dependency issues if a block contained both Size and Checksum
primitives, or in blocks that referenced each other.
Checksum naturally depends on Size's value, but if Size depends on Checksum's
value, we have a recursion problem.

The current design is motivated by the fact that, in reality, Size does not
depend on Checksum's value. Depending on the length method rather than
rendering more closely matches reality.