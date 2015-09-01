import sessions
import serial_connection
import serial_connection_low_level


class SerialTarget(sessions.Target):
    """
    Target class that uses a SerailConnection. Serial messages are assumed to be time-separated, terminated by a
    separator string/regex, or both.
    Encapsulates connection logic for the target, as well as pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().
    """

    def __init__(self, port=0, baudrate=9600, timeout=5, message_separator_time=0.300, content_checker=None):
        """
        @type  port:                   int | str
        @param port:                   Serial port name or number.
        @type baudrate:                int
        @param baudrate:               Baud rate for port.
        @type message_separator_time:  float
        @param message_separator_time: The amount of time to wait before considering a reply from the target complete.
                                       This is different than a timeout, as the message is considered complete, not
                                       timed out.
        @type content_checker:      str
        @param content_checker:     (Optional, def=None) Regex string to search for. When found, indicates a
                                       completed message.
        """
        super(SerialTarget, self).__init__(host="", port=1)

        self._target_connection = serial_connection.SerialConnection(
            connection=serial_connection_low_level.SerialConnectionLowLevel(port=port, baudrate=baudrate),
            timeout=timeout,
            message_separator_time=message_separator_time,
            content_checker=content_checker
        )

        # set these manually once target is instantiated.
        self.netmon = None
        self.procmon = None
        self.vmcontrol = None
        self.netmon_options = {}
        self.procmon_options = {}
        self.vmcontrol_options = {}
