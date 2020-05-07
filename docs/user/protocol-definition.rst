.. _protocol-definition:

Static Protocol Definition
==========================

For the old school Spike-style static protocol definition format, see
:ref:`static protocol definition functions<static-primitives>`. The non-static protocol definition
described here is the newer (but still somewhat experimental) approach.

See the :ref:`Quickstart <quickstart>` guide for an intro to using boofuzz in general and a basic protocol definition
example.

Overview
--------

Requests are messages, Blocks are chunks within a message, and Primitives are the elements (bytes, strings, numbers,
checksums, etc.) that make up a Block/Request.

Example
-------
Here is an example of an HTTP message. It demonstrates how to use Request, Block, and several primitives:

.. code-block:: python

    req = Request("HTTP-Request",children=(
        Block("Request-Line", children=(
            Group("Method", values= ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"]),
            Delim("space-1", " "),
            String("URI", "/index.html"),
            Delim("space-2", " "),
            String("HTTP-Version", "HTTP/1.1"),
            Static("CRLF", "\r\n"),
        )),
        Block("Host-Line", children=(
            String("Host-Key", "Host:"),
            Delim("space", " "),
            String("Host-Value", "example.com"),
            Static("CRLF", "\r\n"),
        )),
        Static("CRLF", "\r\n"),
    ))

Request Manipulation
--------------------

.. autofunction:: boofuzz.Request

Block Manipulation
------------------
.. autofunction:: boofuzz.Block
.. autofunction:: boofuzz.Checksum
.. autofunction:: boofuzz.Repeat
.. autofunction:: boofuzz.Size
.. autofunction:: boofuzz.Aligned

Primitive Definition
--------------------

.. autofunction:: boofuzz.Binary
.. autofunction:: boofuzz.Delim
.. autofunction:: boofuzz.Group
.. autofunction:: boofuzz.Lego
.. autofunction:: boofuzz.Random
.. autofunction:: boofuzz.Static
.. autofunction:: boofuzz.String
.. autofunction:: boofuzz.From_file
.. autofunction:: boofuzz.Bit_field
.. autofunction:: boofuzz.Byte
.. autofunction:: boofuzz.Bytes
.. autofunction:: boofuzz.Word
.. autofunction:: boofuzz.Dword
.. autofunction:: boofuzz.Qword

.. _custom-blocks:

Making Your Own Block/Primitive
-------------------------------

Now I know what you're thinking: "With that many sweet primitives and blocks available, what else could I ever
conceivably need? And yet, I am urged by joy to contribute my own sweet blocks!"

To make your own block/primitive:

1. Create an object that implements :class:`Fuzzable <boofuzz.fuzzable>` or :class:`FuzzableBlock <boofuzz.fuzzable_block>`
2. Optional: Create an accompanying static primitive function. See boofuzz's `__init__.py` file for examples.
3. ???
4. Profit!

If your block depends on references to other blocks, the way a checksum or length field depends on other parts of the
message, see the :class:`Size <boofuzz.Size>` source code for an example of how to avoid recursion issues, and Be
Careful. :)
