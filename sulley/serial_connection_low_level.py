import itarget_connection
import serial


class SerialConnection(itarget_connection.ITargetConnection):
    """
    A basic wrapper for a serial object. This class provides no
    Separated from SerialConnectionGeneric to allow for effective unit testing.
    Implements ITargetConnection.
    """

    def __init__(self, port, baudrate, timeout=None):
        """
        @type  port:                   int | str
        @param port:                   Serial port name or number.
        @type baudrate:                int
        @param baudrate:               Baud rate for port.
        @type timeout:                 float
        @param timeout:                Serial port timeout. See pySerial docs. May be updated after creation.
        """
        self._device = None
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self._logger = None

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._device.close()

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._device = serial.Serial(port=self.port, baudrate=self.baudrate)

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data.
        """
        self._device.timeout = self.timeout
        return self._device.read(size=max_bytes)

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        :param data: Data to send.

        :return: None
        """
        self._device.write(data)

    def set_logger(self, logger):
        """
        Set this object's (and it's aggregated classes') logger.

        Note: Logger is unused, but necessary to fulfill ITargetConnection.

        :param logger: Logger to use.
        :type logger: logging.Logger

        :return: None
        """
        self._logger = logger
