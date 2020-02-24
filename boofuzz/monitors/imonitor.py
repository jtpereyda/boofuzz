import abc

from future.utils import with_metaclass


class IMonitor(with_metaclass(abc.ABCMeta, object)):
    """
    Interface for Target monitors. All Monitors must adhere
    to this specification.

    .. versionadded:: 0.2.0
    """

    def __init__(self):
        return

    @abc.abstractmethod
    def alive(self):
        """
        Called when a Target containing this Monitor is added to a session.
        Use this function to connect to e.g. RPC hosts if your target lives
        on another machine.

        You MUST return True if the monitor is alive. You MUST return False
        otherwise. If a Monitor is not alive, this method will be called
        until it becomes alive or throws an exception. You SHOULD handle
        timeouts / connection retry limits in the monitor implementation.

        :returns: Bool
        """
        pass

    @abc.abstractmethod
    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        Called before the current fuzz node is transmitted.

        :returns: None
        """
        pass

    @abc.abstractmethod
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        Called after the current fuzz node is transmitted. Use it to collect
        data about a target and decide whether it crashed.

        You MUST return True if the Target is still alive. You MUST return False
        if the Target crashed. If one Monitor reports a crash, the whole testcase
        will be marked as crashing.

        :returns: Bool
        """
        pass

    @abc.abstractmethod
    def retrieve_data(self):
        """
        Called to retrieve data independent of whether the current fuzz node crashed
        the target or not. Called before the fuzzer proceeds to a new testcase.

        You SHOULD return any auxillary data that should be recorded. The data MUST
        be serializable, e.g. bytestring.
        """
        pass

    @abc.abstractmethod
    def set_options(self, *args, **kwargs):
        """
        Called to set options for your monitor (e.g. local crash dump storage).
        \*args and \*\*kwargs can be explicitely specified by implementing classes,
        however you SHOULD ignore any kwargs you do not recognize.

        :returns: None
        """
        pass

    def get_crash_synopsis(self):
        """
        Called if any monitor indicates that the current testcase has failed,
        even if this monitor did not detect a crash. You SHOULD return a human-
        readable representation of the crash synopsis (e.g. hexdump). You MAY
        save the full crashdump somewhere.

        :returns: str
        """
        return ""

    def start_target(self):
        """
        Starts a target. You MUST return True if the start was successful. You
        MUST return False if not. Monitors will be tried to start the target
        in the order they were added to the Target; the first Monitor to succeed
        breaks iterating.

        :returns: Bool
        """
        return False

    def stop_target(self):
        """
        Stops a target. You MUST return True if the stop was successful. You
        MUST return False if not. Monitors will be tried to stop the target
        in the order they were added to the Target; the first Monitor to succeed
        breaks iterating.

        :returns: Bool
        """

        return False

    @abc.abstractmethod
    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        """
        Restart a target. Must return True if restart was successful, False if it was unsucessful
        or this monitor cannot restart a Target, which causes the next monitor in the chain
        to try to restart.

        The first successful monitor causes the restart chain to stop applying.

        :returns: Bool
        """
        pass
