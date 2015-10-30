Size Class
==========
The Size class creates a block that calculates the size of another block.

Recursion
---------
To enable a size to be calculated over a Size block's parent block, it is
necessary to account for recursion.
This is done with a recursion flag.

When Size renders its target block for the sake of calculations, it will set a
recursion flag on itself.
Then, if the target block again renders the Size block, the size block will
check its own recursion flag and return its default value.