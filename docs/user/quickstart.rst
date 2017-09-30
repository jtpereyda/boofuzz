.. _quickstart:

Quickstart
==========

The :class:`Session <boofuzz.Session>` object is the center of your fuzz... session. When you create it,
you'll pass it a :class:`Target <boofuzz.Target>` object, which will itself receive a :ref:`Connection <connections>` object. For example: ::

    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 8021, proto='tcp')))

Connection objects implement :class:`ITargetConnection <boofuzz.ITargetConnection>`. Available options include
:class:`SocketConnection <boofuzz.SocketConnection>` and :class:`SerialConnection <boofuzz.SerialConnection>`.

With a Session object ready, you next need to define the messages in your protocol. Once you've read the requisite
RFC, tutorial, etc., you should be confident enough in the format to define your protocol using the various
:ref:`static protocol definition functions<static-primitives>`.

Each message starts with an :meth:`s_initialize <boofuzz.s_initialize>` function.

Here are several message definitions from the FTP protocol: ::

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

Once you've defined your message(s), you will connect them into a graph using the Session object you just created.::

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))

After that, you are ready to fuzz: ::

    session.fuzz()

Note that at this point you have only a very basic fuzzer. Making it kick butt is up to you.

To do cool stuff like checking responses, you'll want to use :meth:`Session.post_send <boofuzz.Session.post_send>`.
You may also want be interested in :ref:`custom-blocks`.

Remember boofuzz is all Python, so everything is there for your customization.
If you are doing crazy cool stuff, check out the :ref:`community info <community>` and consider contributing back!

Happy fuzzing, and Godspeed!