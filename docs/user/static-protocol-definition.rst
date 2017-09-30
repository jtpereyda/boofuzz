.. _static-primitives:

Static Protocol Definition
==========================

Static functions are used in boofuzz to assemble messages for a protocol definition. They may be obsoleted in future
releases by a less static approach to message construction. For now, you can see the :ref:`Quickstart <quickstart>`
guide for an intro.

Requests are messages, Blocks are chunks within a message, and Primitives are the elements (bytes, strings, numbers,
checksums, etc.) that make up a Block/Request.

Request Manipulation
--------------------

.. autofunction:: boofuzz.s_initialize
.. autofunction:: boofuzz.s_get
.. autofunction:: boofuzz.s_mutate
.. autofunction:: boofuzz.s_num_mutations
.. autofunction:: boofuzz.s_render
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
.. autofunction:: boofuzz.s_word
.. autofunction:: boofuzz.s_dword
.. autofunction:: boofuzz.s_qword

.. _custom-blocks:

Making Your Own Block/Primitive
-------------------------------

Now I know what you're thinking: "With that many sweet primitives and blocks available, what else could I ever
conceivably need? And yet, I am urged by joy to contribute my own sweet blocks!"

To make your own block/primitive:

1. Create an object that implements :class:`IFuzzable <boofuzz.ifuzzable>`.
2. Create an accompanying static primitive function. See boofuzz's `__init__.py` file for examples.
3. ???
4. Profit!

If your block depends on references to other blocks, the way a checksum or length field depends on other parts of the
message, see the :class:`Size <boofuzz.Size>` source code for an example of how to avoid recursion issues. Or otherwise
be careful. :)