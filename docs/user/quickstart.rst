.. _quickstart:

Quickstart
==========

The :class:`Session <boofuzz.Session>` object is the center of your fuzz... session. When you create it,
you'll pass it a :class:`Target <boofuzz.Target>` object, which will itself receive a :ref:`Connection <connections>`
object. For example:

.. code-block:: python

    session = Session(
        target=Target(
            connection=TCPSocketConnection("127.0.0.1", 8021)))

Connection objects implement :class:`ITargetConnection <boofuzz.connections.ITargetConnection>`. Available options
include :class:`TCPSocketConnection <boofuzz.connections.TCPSocketConnection>` and its sister classes for UDP, SSL and
raw sockets, and :class:`SerialConnection <boofuzz.connections.SerialConnection>`.

With a Session object ready, you next need to define the messages in your protocol. Once you've read the requisite
RFC, tutorial, etc., you should be confident enough in the format to define your protocol using the various
:ref:`block and primitive types <protocol-definition>`.

Each message is a :class:`Request <boofuzz.Request>` object, whose children define the structure for that
message.

Here are several message definitions from the FTP protocol:

.. code-block:: python

    user = Request("user", children=(
        String("key", "USER"),
        Delim("space", " "),
        String("val", "anonymous"),
        Static("end", "\r\n"),
    ))

    passw = Request("pass", children=(
        String("key", "PASS"),
        Delim("space", " "),
        String("val", "james"),
        Static("end", "\r\n"),
    ))

    stor = Request("stor", children=(
        String("key", "STOR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

    retr = Request("retr", children=(
        String("key", "RETR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

Once you've defined your message(s), you will connect them into a graph using the Session object you just created:

.. code-block:: python

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)

When fuzzing, boofuzz will send ``user`` before fuzzing ``passw``, and ``user`` and
``passw`` before fuzzing ``stor`` or ``retr``.

Now you are ready to fuzz:

.. code-block:: python

    session.fuzz()

Note that at this point you have only a very basic fuzzer. Making it kick butt is up to you. There are some
`examples <https://github.com/jtpereyda/boofuzz/tree/master/examples>`_ and
`request_definitions <https://github.com/jtpereyda/boofuzz/tree/master/request_definitions>`_ in the repository that
might help you get started.

The log data of each run will be saved to a SQLite database located in the **boofuzz-results** directory in your
current working directory. You can reopen the web interface on any of those databases at any time with

.. code-block:: bash

    $ boo open <run-*.db>

To do cool stuff like checking responses, you'll want to use ``post_test_case_callbacks`` in
:class:`Session <boofuzz.Session>`. To use data from a response in a subsequent request, see
:class:`ProtocolSessionReference <boofuzz.ProtocolSessionReference>`.

You may also be interested in :ref:`custom-blocks`.

Remember boofuzz is all Python, and advanced use cases often require customization.
If you are doing crazy cool stuff, check out the :ref:`community info <community>` and consider contributing back!

Happy fuzzing, and Godspeed!
