import abc


class IFuzzLogger(object):
    """
    Abstract class for logging fuzz data.

    Usage while testing:
     1. Open test case.
     2. Open test step.
     3. Use other log methods.

    IFuzzLogger provides the logging interface for the Sulley framework and
    test writers.

    The methods provided are meant to mirror functional test actions. Instead of
    generic debug/info/warning methods, IFuzzLogger provides a means for logging
    test cases, passes, failures, test steps, etc.

    This hypothetical sample output gives an idea of how the logger should be
    used:

    Test Case: UDP.Header.Address 3300
        Test Step: Fuzzing
            Send: 45 00 13 ab 00 01 40 00 40 11 c9 ...
        Test Step: Process monitor check
            Check OK
        Test Step: DNP Check
            Send: ff ff ff ff ff ff 00 0c 29 d1 10 ...
            Recv: 00 0c 29 d1 10 81 00 30 a7 05 6e ...
            Check: Reply is as expected.
            Check OK
    Test Case: UDP.Header.Address 3301
        Test Step: Fuzzing
            Send: 45 00 13 ab 00 01 40 00 40 11 c9 ...
        Test Step: Process monitor check
            Check Failed: "Process returned exit code 1"
        Test Step: DNP Check
            Send: ff ff ff ff ff ff 00 0c 29 d1 10 ...
            Recv: None
            Check: Reply is as expected.
            Check Failed

    A test case is opened for each fuzzing case. A test step is opened for each
    high-level test step. Test steps can include, for example:

    * Fuzzing
    * Set up (pre-fuzzing)
    * Post-test cleanup
    * Instrumentation checks
    * Reset due to failure

    Within a test step, a test may log data sent, data received, checks, check
    results, and other information.

    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        """
        Open a test case - i.e., a fuzzing mutation.

        Args:
            test_case_id: Test case name/number. Should be unique.
            name (str): Human readable and unique name for test case.
            index (int): Numeric index for test case

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
