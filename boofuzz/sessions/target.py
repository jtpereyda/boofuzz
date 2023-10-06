import time
import warnings


class Target:
    """Target descriptor container.

    Takes an ITargetConnection and wraps send/recv with appropriate
    FuzzDataLogger calls.

    Encapsulates pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().

    Example:
        tcp_target = Target(SocketConnection(host='127.0.0.1', port=17971))

    Args:
        connection (itarget_connection.ITargetConnection): Connection to system under test.
        monitors (List[Union[IMonitor, pedrpc.Client]]): List of Monitors for this Target.
        monitor_alive: List of Functions that are called when a Monitor is alive. It is passed
                          the monitor instance that became alive. Use it to e.g. set options
                          on restart.
        repeater (repeater.Repeater): Repeater to use for sending. Default None.
        procmon: Deprecated interface for adding a process monitor.
        procmon_options: Deprecated interface for adding a process monitor.

    .. versionchanged:: 0.4.2
       This class has been moved into the sessions subpackage. The full path is now boofuzz.sessions.target.Target.
    """

    def __init__(
        self,
        connection,
        monitors=None,
        monitor_alive=None,
        max_recv_bytes=10000,
        repeater=None,
        procmon=None,
        procmon_options=None,
        **kwargs
    ):
        self._fuzz_data_logger = None

        self._target_connection = connection
        self.max_recv_bytes = max_recv_bytes
        self.repeater = repeater
        self.monitors = monitors if monitors is not None else []
        if procmon is not None:
            if procmon_options is not None:
                procmon.set_options(**procmon_options)
            self.monitors.append(procmon)

        self.monitor_alive = monitor_alive if monitor_alive is not None else []

        if "procmon" in kwargs.keys() and kwargs["procmon"] is not None:
            warnings.warn(
                "Target(procmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["procmon"])

        if "netmon" in kwargs.keys() and kwargs["netmon"] is not None:
            warnings.warn(
                "Target(netmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["netmon"])

        # set these manually once target is instantiated.
        self.vmcontrol = None
        self.vmcontrol_options = {}

    @property
    def netmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab netmon from monitors and use set_options(**dict)"
        )

    @property
    def procmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab procmon from monitors and use set_options(**dict)"
        )

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._fuzz_data_logger.log_info("Closing target connection...")
        self._target_connection.close()
        self._fuzz_data_logger.log_info("Connection closed.")

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._fuzz_data_logger.log_info("Opening target connection ({0})...".format(self._target_connection.info))
        self._target_connection.open()
        self._fuzz_data_logger.log_info("Connection opened.")

    def pedrpc_connect(self):
        warnings.warn(
            "pedrpc_connect has been renamed to monitors_alive. "
            "This alias will stop working in a future version of boofuzz.",
            FutureWarning,
        )

        return self.monitors_alive()

    def monitors_alive(self):
        """
        Wait for the monitors to become alive / establish connection to the RPC server.
        This method is called on every restart of the target and when it's added to a session.
        After successful probing, a callback is called, passing the monitor.

        :return: None
        """
        for monitor in self.monitors:
            while True:
                if monitor.alive():
                    break
                time.sleep(1)

            if self.monitor_alive:
                for cb in self.monitor_alive:
                    cb(monitor)

    def recv(self, max_bytes=None):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        if max_bytes is None:
            max_bytes = self.max_recv_bytes

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("Receiving...")

        data = self._target_connection.recv(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            None
        """
        num_sent = 0
        if self._fuzz_data_logger is not None:
            repeat = ""
            if self.repeater is not None:
                repeat = ", " + self.repeater.log_message()

            self._fuzz_data_logger.log_info("Sending {0} bytes{1}...".format(len(data), repeat))

        if self.repeater is not None:
            self.repeater.start()
            while self.repeater.repeat():
                num_sent = self._target_connection.send(data=data)
            self.repeater.reset()
        else:
            num_sent = self._target_connection.send(data=data)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data[:num_sent])

    def set_fuzz_data_logger(self, fuzz_data_logger):
        """
        Set this object's fuzz data logger -- for sent and received fuzz data.

        :param fuzz_data_logger: New logger.
        :type fuzz_data_logger: ifuzz_logger.IFuzzLogger

        :return: None
        """
        self._fuzz_data_logger = fuzz_data_logger
