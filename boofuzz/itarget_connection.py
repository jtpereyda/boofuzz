import abc


class ITargetConnection(object):
    """
    Interface for connections to fuzzing targets.
    Target connections may be opened and closed multiple times. You must open before using send/recv and close
    afterwards.
    """
    __metaclass__ = abc.ABCMeta

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
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send(self, data):
        """
        Send data to the target.

        :param data: Data to send.

        :rtype int
        :return: Number of bytes actually sent.
        """
        raise NotImplementedError

    @abc.abstractproperty
    def info(self):
        """Return description of connection info.

        E.g., "127.0.0.1:2121"

        Returns:
            str: Connection info descrption
        """
        raise NotImplementedError
