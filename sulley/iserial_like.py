import abc


class ISerialLike(object):
    """
    A serial-like interface, based on the pySerial module,
    the notable difference being that open() must always be called after the object is first created.

    Facilitates dependency injection in modules that use pySerial.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def close(self):
        """
        Close connection to the target.

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
        Receive up to max_bytes data from the target.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        :param data: Data to send.

        :return: Number of bytes actually sent.
        """
        raise NotImplementedError
