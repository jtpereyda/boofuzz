import sessions
import serial_connection


class SerialTarget(sessions.Target):
    """
    Target class that uses a SerailConnection.
    Encapsulates connection logic for the target, as well as pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().
    """

    def __init__(self, port=0, baudrate=9600):
        """
        @type  port: int | str
        @param port: Serial port name or number.
        @type baudrate: int
        @param baudrate: Baud rate for port.
        """
        super(SerialTarget, self).__init__(host="", port=1)

        self.target_connection = serial_connection.SerialConnection(port=port, baudrate=baudrate)

        # set these manually once target is instantiated.
        self.netmon = None
        self.procmon = None
        self.vmcontrol = None
        self.netmon_options = {}
        self.procmon_options = {}
        self.vmcontrol_options = {}
