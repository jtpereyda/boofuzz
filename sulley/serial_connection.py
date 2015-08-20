import itarget_connection
import serial


class SerialConnection(itarget_connection.ITargetConnection):
    """
    ITargetConnection implementation using serial ports.

    Messages are time-delimited, based on a parameter given to the constructor.
    """

    def __init__(self, port, baudrate, message_separator_time=0.300):
        """
        @type  port:                   int | str
        @param port:                   Serial port name or number.
        @type baudrate:                int
        @param baudrate:               Baud rate for port.
        @type message_separator_time:  float
        @param message_separator_time: The amount of time to wait before considering a reply from the target complete.
        """
        self._device = None
        self.port = port
        self.baudrate = baudrate
        self.logger = None
        self.message_separator_time = message_separator_time

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

        self._device.timeout = self.message_separator_time

        fragment = self._device.read(size=1024)
        data = fragment

        # Serial ports can be slow and render only a few bytes at a time.
        # Therefore, we keep reading until we get nothing, in hopes of getting a full packet.
        while fragment:
            fragment = self._device.read(size=1024)
            data += fragment

        return data

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

        :param logger: Logger to use.
        :type logger: logging.Logger

        :return: None
        """
        self.logger = logger
