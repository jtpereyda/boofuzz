import errno
import pickle
import select
import socket
import struct
import sys
import time
import uuid

from boofuzz import exception


class Client(object):
    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__dbg_flag = False
        self.__server_sock = None
        self.__retry = 0
        self.NOLINGER = struct.pack("ii", 1, 0)
        self.known_server = None

    def __getattr__(self, method_name):
        """
        This routine is called by default when a requested attribute (or method) is accessed that has no definition.
        Unfortunately __getattr__ only passes the requested method name and not the arguments. So we extend the
        functionality with a little lambda magic to the routine method_missing(). Which is actually how Ruby handles
        missing methods by default ... with arguments. Now we are just as cool as Ruby.

        @type  method_name: str
        @param method_name: The name of the requested and undefined attribute (or method in our case).

        @rtype:  lambda
        @return: Lambda magic passing control (and in turn the arguments we want) to self.method_missing().
        """

        return lambda *args, **kwargs: self.__method_missing(method_name, *args, **kwargs)

    def __connect(self):
        """
        Connect to the PED-RPC server.
        """

        # if we have a pre-existing server socket, ensure it's closed.
        self.__disconnect()

        # connect to the server, timeout on failure.
        self.__server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__server_sock.settimeout(3.0)
        try:
            self.__server_sock.connect((self.__host, self.__port))
        except socket.error as e:
            if self.__retry != 5:
                self.__retry += 1
                time.sleep(5)
                self.__connect()
            else:
                raise exception.BoofuzzRpcError(
                    'PED-RPC> unable to connect to server {0}:{1}. Error message: "{2}"\n'.format(
                        self.__host, self.__port, e
                    )
                )
        # disable timeouts and lingering.
        self.__server_sock.settimeout(None)
        self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.NOLINGER)

    def __disconnect(self):
        """
        Ensure the socket is torn down.
        """

        if self.__server_sock is not None:
            self.__debug("closing server socket")
            self.__server_sock.close()
            self.__server_sock = None

    def __debug(self, msg):
        if self.__dbg_flag:
            print("PED-RPC> %s" % msg)

    def __method_missing(self, method_name, *args, **kwargs):
        """
        See the notes for __getattr__ for related notes. This method is called, in the Ruby fashion, with the method
        name and arguments for any requested but undefined class method.

        @type  method_name: str
        @param method_name: The name of the requested and undefined attribute (or method in our case).
        @type  *args:       tuple
        @param *args:       Tuple of arguments.
        @type  **kwargs     dict
        @param **kwargs:    Dictioanry of arguments.

        @rtype:  Mixed
        @return: Return value of the mirrored method.
        """

        # return a value so lines of code like the following work:
        #     x = pedrpc.client(host, port)
        #     if x:
        #         x.do_something()
        if method_name == "__bool__":
            return 1

        # subclasses run into this as they call a trampoline method...
        # not sure if this is the right way to handle it, but it seems to work
        if method_name.endswith("__method_missing"):
            return self.__method_missing(*args, **kwargs)
        elif method_name.endswith("__hot_transmit"):
            return self.__hot_transmit(*args, **kwargs)

        # ignore all other attempts to access a private member.
        if method_name.startswith("__"):
            return

        # connect to the PED-RPC server.
        self.__connect()

        server_uuid = self.__pickle_recv()
        if server_uuid != self.known_server:
            self.on_new_server(server_uuid)
            self.known_server = server_uuid

        # transmit the method name and arguments.
        self.__pickle_send((method_name, (args, kwargs)))

        # snag the return value.
        ret = self.__pickle_recv()

        # close the sock and return.
        self.__disconnect()
        return ret

    def __hot_transmit(self, data):
        self.__pickle_send(data)
        self.__pickle_recv()
        self.__disconnect()
        self.__connect()
        # Grab the instance id. assume it hasn't changed, otherwise we're doomed.
        self.__pickle_recv()

    def __pickle_recv(self):
        """
        This routine is used for marshaling arbitrary data from the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        """

        try:
            # TODO: this should NEVER fail, but alas, it does and for the time being i can't figure out why.
            #       it gets worse. you would think that simply returning here would break things, but it doesn't.
            #       gotta track this down at some point.
            recvd = self.__server_sock.recv(4)
            length = struct.unpack("<L", recvd)[0]
        except Exception:
            return

        try:
            received = b""

            while length:
                chunk = self.__server_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except socket.error as e:
            raise exception.BoofuzzRpcError(
                "PED-RPC> unable to connect to server "
                '{0}:{1}. Error message: "{2}"\n'.format(self.__host, self.__port, e)
            )

        return pickle.loads(received)

    def __pickle_send(self, data):
        """
        This routine is used for marshaling arbitrary data to the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        """

        data = pickle.dumps(data, protocol=2)
        self.__debug("sending %d bytes" % len(data))

        try:
            self.__server_sock.send(struct.pack("<L", len(data)))
            self.__server_sock.send(data)
        except socket.error as e:
            raise exception.BoofuzzRpcError(
                "PED-RPC> unable to connect to server "
                '{0}:{1}. Error message: "{2}"\n'.format(self.__host, self.__port, e)
            )

    def on_new_server(self, new_server):
        """ Override this Method in a child class to be notified when the RPC server was restarted. """
        return


class Server(object):
    """
    The main PED-RPC Server class. To implement an RPC server, inherit from this class. Call ``serve_forever`` to start
    listening for RPC commands.
    """

    def __init__(self, host, port):
        self.__host = host
        self.__port = port
        self.__dbg_flag = False
        self.__client_sock = None
        self.__client_address = None
        self.__running = True

        # This is a bad solution for a problem that should not even exist in the first place.
        # The Problem is that the client disconnects after each RPC call,
        # and reconnects on the next without any way to know if the state
        # of the RPC server has changed. This becomes a problem if e.g.
        # a Virtual Machine with automatic restarting is used in conjunction
        # with a Monitor that runs a RPC daemon on the target. In this case,
        # a monitor may want to ensure that a set of options are in a known
        # state on the target.
        # For this to work, the client needs to know if the server has changed
        # since the last time it connected to it so it can notify the implementation
        # to re-send any initialisation code. This is implemented by the server
        # generating a random uuid on startup and sending it to each new connection.
        #
        # In a perfect world, this protocol wouldn't reconnect for every command
        # and options were associated with a connection, but at the moment I don't
        # feel like cleaning up this mess.
        self.__instance = uuid.uuid4()

        try:
            # create a socket and bind to the specified port.
            self.__server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__server.settimeout(None)
            self.__server.bind((host, port))
            self.__server.listen(1)
        except socket.error:
            sys.stderr.write("unable to bind to %s:%d\n" % (host, port))
            sys.exit(1)

    def __disconnect(self):
        """
        Ensure the socket is torn down.
        """

        if self.__client_sock is not None:
            self.__debug("closing client socket")
            try:
                self.__client_sock.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                if e.errno in [errno.ENOTCONN, errno.EBADF]:
                    pass
                else:
                    raise
            self.__client_sock.close()

    def __debug(self, msg):
        if self.__dbg_flag:
            print("PED-RPC> %s" % msg)

    def __pickle_recv(self):
        """
        This routine is used for marshaling arbitrary data from the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @raise pdx: An exception is raised if the connection was severed.
        @rtype:     Mixed
        @return:    Whatever is received over the socket.
        """

        try:
            length = struct.unpack("<L", self.__client_sock.recv(4))[0]
            received = b""

            while length:
                chunk = self.__client_sock.recv(length)
                received += chunk
                length -= len(chunk)
        except Exception:
            sys.stderr.write("PED-RPC> connection client severed during recv()\n")
            raise Exception

        return pickle.loads(received)

    def __pickle_send(self, data):
        """
        This routine is used for marshaling arbitrary data to the PyDbg server. We can send pretty much anything here.
        For example a tuple containing integers, strings, arbitrary objects and structures. Our "protocol" is a simple
        length-value protocol where each datagram is prefixed by a 4-byte length of the data to be received.

        @type  data: Mixed
        @param data: Data to marshal and transmit. Data can *pretty much* contain anything you throw at it.

        @raise pdx: An exception is raised if the connection was severed.
        """

        data = pickle.dumps(data, protocol=2)
        self.__debug("sending %d bytes" % len(data))

        try:
            self.__client_sock.send(struct.pack("<L", len(data)))
            self.__client_sock.send(data)
        except Exception:
            sys.stderr.write("PED-RPC> connection to client severed during send()\n")
            raise Exception

    def serve_forever(self):
        self.__debug("serving up a storm")

        while self.__running:
            # close any pre-existing socket.
            self.__disconnect()

            # accept a client connection.
            while self.__running:
                readable, writeable, errored = select.select([self.__server], [], [], 0.1)
                if len(readable) > 0:
                    assert readable[0] == self.__server
                    (self.__client_sock, self.__client_address) = self.__server.accept()
                    break

            self.__debug("accepted connection from %s:%d" % (self.__client_address[0], self.__client_address[1]))

            self.__pickle_send(self.__instance)

            # receive the method name and arguments, continue on socket disconnect.
            try:
                (method_name, (args, kwargs)) = self.__pickle_recv()
                self.__debug("%s(args=%s, kwargs=%s)" % (method_name, args, kwargs))
            except Exception:
                continue

            try:
                method = getattr(self, method_name)
            except AttributeError:
                # if the method can't be found notify the user and raise an error
                sys.stderr.write('PED-RPC> remote method "{0}" of {1} cannot be found\n'.format(method_name, self))
                raise
            ret = method(*args, **kwargs)
            # transmit the return value to the client, continue on socket disconnect.
            try:
                self.__pickle_send(ret)
            except Exception:
                continue

    def stop(self):
        self.__running = False
        self.__disconnect()
        try:
            self.__server.shutdown(socket.SHUT_RDWR)
        except socket.error as e:
            if e.errno == errno.ENOTCONN:
                pass
            else:
                raise
        self.__server.close()
