import abc


class IFuzzLogger(object):
    """
    Abstract class for logging fuzz data.

    Usage while testing:
     1. Open test case.
     2. Open test step.
     3. Use other log methods.
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
    def open_test_step(self, description):
        """
        Open a test step - e.g., "Fuzzing", "Pre-fuzz", "Response Check."

        :param description: Description of fuzzing step.

        :return: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_send(self, data):
        """
        Records data as about to be sent to the target.

        :param data: Transmitted data
        :type data: bytes

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_recv(self, data):
        """
        Records data as having been received from the target.

        :param data: Received data.
        :type data: bytes

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_check(self, description):
        """
        Records a check on the system under test. AKA "instrumentation check."

        :param description: Received data.
        :type description: str

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_pass(self, description=""):
        """
        Records a check that passed.

        :param description: Optional supplementary data..
        :type description: str

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_fail(self, description=""):
        """
        Records a check that failed. This will flag a fuzzing case as a
        potential bug or anomaly.

        :param description: Optional supplementary data.
        :type description: str

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_info(self, description):
        """
        Catch-all method for logging test information

        :param description: Information.
        :type description: str

        :return: None
        :rtype: None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def log_error(self, description):
        """
        Records an internal error. This informs the operaor that the test was
        not completed successfully.

        :param description: Received data.
        :type description: str

        :return: None
        :rtype: None
        """
        raise NotImplementedError
