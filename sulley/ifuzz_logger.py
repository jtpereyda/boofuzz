import abc


class IFuzzLogger(object):
    """
    Abstract class for logging fuzz data. Allows for logging approaches.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def open_test_case(self, test_case_id):
        """
        Open a test case - i.e., a fuzzing mutation.

        :param test_case_id: Test case name/number. Should be unique.

        :return: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_send(self, data):
        """
        Records data as about to be sent to the target.

        :param data: Transmitted data
        :type data: buffer

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_recv(self, data):
        """
        Records data as having been received from the target.

        :param data: Received data.
        :type data: buffer

        :return: None
        :rtype: None
        """
        raise NotImplementedError
