import ifuzz_logger
import os
import errno


class FuzzLoggerFile(ifuzz_logger.IFuzzLogger):
    """
    Deprecated: Use FuzzLogger with FuzzLoggerText for typical fuzz logging.

    IFuzzLogger that saves sent and received data to files within a directory.

    File format is: <mutation nubmer>-(rx|tx)-<sequence number>.txt
    """

    def log_error(self, description):
        raise Exception("FuzzLoggerFile does not support log_error()!")

    def open_test_step(self, description):
        raise Exception("FuzzLoggerFile does not support open_test_step()!")

    def log_fail(self, description=""):
        raise Exception("FuzzLoggerFile does not support log_fail()!")

    def log_info(self, description):
        raise Exception("FuzzLoggerFile does not support log_info()!")

    def log_pass(self, description=""):
        raise Exception("FuzzLoggerFile does not support log_pass()!")

    def log_check(self, description):
        raise Exception("FuzzLoggerFile does not support log_check()!")

    def __init__(self, path):
        """
        :param path: Directory in which to save fuzz data.
        """
        self._path = path
        self._current_id = ''
        self._rx_count = 0
        self._tx_count = 0

        # mkdir -p self._path
        try:
            os.makedirs(self._path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        """
        Open a test case - i.e., a fuzzing mutation.

        :param test_case_id: Test case name/number. Should be unique.

        :return: None
        """
        self._current_id = str(test_case_id)
        self._rx_count = 0
        self._tx_count = 0

    def log_send(self, data):
        """
        Records data as about to be sent to the target.

        :param data: Transmitted data
        :type data: bytes

        :return: None
        :rtype: None
        """
        self._tx_count += 1

        filename = "{0}-tx-{1}.txt".format(self._current_id, self._tx_count)
        full_name = os.path.join(self._path, filename)

        # Write data in binary mode to avoid newline conversion
        with open(full_name, "wb") as file_handle:
            file_handle.write(data)

    def log_recv(self, data):
        """
        Records data as having been received from the target.

        :param data: Received data.
        :type data: bytes

        :return: None
        :rtype: None
        """
        self._rx_count += 1

        filename = "{0}-rx-{1}.txt".format(self._current_id, self._tx_count)
        full_name = os.path.join(self._path, filename)

        # Write data in binary mode to avoid newline conversion
        with open(full_name, "wb") as file_handle:
            file_handle.write(data)
