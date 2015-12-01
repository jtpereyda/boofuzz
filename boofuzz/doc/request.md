Request Class
=============

Building
--------
The Request class has push and pop methods for creating it.
Whenever a new Block is opened/started, it is pushed onto the "block stack".
Note that this is different than the "stack".
When a Block is closed, it is popped.

When the Request is assembled in the fuzz definition, its stack should be empty.
To accomplish this, all blocks should be closed.