.. _static-primitives:

Static Protocol Definition
==========================

Protocol definition via static functions in boofuzz is inherited from Spike. See
:ref:`protocol definition functions<protocol-definition>` for a newer, if still experimental, format.

See the :ref:`Quickstart <quickstart>` guide for an intro to using boofuzz in general.

Requests are messages, Blocks are chunks within a message, and Primitives are the elements (bytes, strings, numbers,
checksums, etc.) that make up a Block/Request.

Request Manipulation
--------------------

.. autofunction:: boofuzz.s_initialize
.. autofunction:: boofuzz.s_get
.. autofunction:: boofuzz.s_num_mutations
.. autofunction:: boofuzz.s_switch

Block Manipulation
------------------
.. autofunction:: boofuzz.s_block
.. autofunction:: boofuzz.s_block_start
.. autofunction:: boofuzz.s_block_end
.. autofunction:: boofuzz.s_checksum
.. autofunction:: boofuzz.s_repeat
.. autofunction:: boofuzz.s_size
.. autofunction:: boofuzz.s_update

Primitive Definition
--------------------

.. autofunction:: boofuzz.s_binary
.. autofunction:: boofuzz.s_delim
.. autofunction:: boofuzz.s_group
.. autofunction:: boofuzz.s_lego
.. autofunction:: boofuzz.s_random
.. autofunction:: boofuzz.s_static
.. autofunction:: boofuzz.s_string
.. autofunction:: boofuzz.s_from_file
.. autofunction:: boofuzz.s_bit_field
.. autofunction:: boofuzz.s_byte
.. autofunction:: boofuzz.s_bytes
.. autofunction:: boofuzz.s_word
.. autofunction:: boofuzz.s_dword
.. autofunction:: boofuzz.s_qword
