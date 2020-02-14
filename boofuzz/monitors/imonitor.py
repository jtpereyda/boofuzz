import abc

from future.utils import with_metaclass

class IMonitor(with_metaclass(abc.ABCMeta, object)):
    """
    Interface for Target monitors.
    """

    @abc.abstractmethod
    def alive(self):
        pass

    @abc.abstractmethod
    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        pass

    @abc.abstractmethod
    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        pass

    @abc.abstractmethod
    def retrieve_data(self):
        pass

    @abc.abstractmethod
    def set_options(self, *args, **kwargs):
        pass

    def get_crash_synopsis(self):
        return ""

    def start_target(self):
        return False

    def stop_target(self):
        return False

    @abc.abstractmethod
    def restart_target(self):
        """
        Restart a target. Must return True if restart was successful, False if it was unsucessful
        or this monitor cannot restart a Target, which causes the next monitor in the chain
        to try to restart.

        The first successful monitor causes the restart chain to stop applying.

        :returns: Bool
        """
        pass

class MonitorError(Exception):
    pass
