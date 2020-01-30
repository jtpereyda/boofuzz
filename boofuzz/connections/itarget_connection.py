import abc

from future.utils import with_metaclass


# abc.ABCMeta is the metaclass in both python 2 and 3
class ITargetConnection(with_metaclass(abc.ABCMeta, object)):
    """
    Interface for connections to fuzzing targets.
    Target connections may be opened and closed multiple times. You must open before using send/recv and close
    afterwards.

    .. versionchanged:: 0.2.0
        ITargetConnection has been moved into the connections subpackage.
        The full path is now boofuzz.connections.itarget_connection.ITargetConnection
    """

    @abc.abstractmethod
    def close(self):
        """
        Close connection.

        :return: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def recv(self, max_bytes):
        """
        Receive up to max_bytes data.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data. bytes('') if no data is received.
        :rtype: bytes
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send(self, data):
        """
        Send data to the target.

        :param data: Data to send.

        :return: Number of bytes actually sent.
        :rtype: int
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def info(self):
        """Return description of connection info.

        E.g., "127.0.0.1:2121"

        Returns:
            str: Connection info descrption
        """
        raise NotImplementedError
