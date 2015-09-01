import sessions
import serial_connection
import serial_connection_low_level


class SerialTarget(sessions.Target):
    """
    Target class that uses a serial_connection.SerialConnection. Serial messages are assumed to be time-separated,
    terminated by a separator string/regex, or both.
    Encapsulates connection logic for the target. Inherits pedrpc connection logic from sessions.Target.

    Contains a logger which is configured by Session.add_target().
    """

    def __init__(self, port=0, baudrate=9600, timeout=5, message_separator_time=0.300, content_checker=None):
        """
        See serial_connection.SerialConnection for details on timeout, message_separator_time, and content_checker.

        @type  port:                   int | str
        @param port:                   Serial port name or number.

        @type baudrate:                int
        @param baudrate:               Baud rate for port.

        @type timeout:                 float
        @param timeout:                For recv(). After timeout seconds from receive start,
                                       recv() will return all received data, if any.

        @type message_separator_time:  float
        @param message_separator_time: (Optional, def=None)
                                       After message_separator_time seconds _without receiving any more data_,
                                       recv() will return.

        @type content_checker:         function(str) -> int
        @param content_checker:        (Optional, def=None) User-defined function.
                                           recv() will pass all bytes received so far to this method.
                                           If the method returns n > 0, recv() will return n bytes.
                                           If it returns 0, recv() will keep on reading.
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
