from __future__ import print_function
import time
from sulley import ifuzz_logger_backend
from sulley import helpers
import sys

DEFAULT_HEX_TO_STR = helpers.hex_str


def get_time_stamp():
    t = time.time()
    s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(t))
    s += ",%03d]" % (t * 1000 % 1000)
    return s


class FuzzLoggerText(ifuzz_logger_backend.IFuzzLoggerBackend):
    TEST_CASE_FORMAT = "Test Case: {0}"
    TEST_STEP_FORMAT = "Test Step: {0}"
    LOG_CHECK_FORMAT = "Check: {0}"
    LOG_INFO_FORMAT = "Info: {0}"
    LOG_PASS_FORMAT = "Check OK {0}"
    LOG_FAIL_FORMAT = "Check Failed {0}"
    LOG_RECV_FORMAT = "Transmitting: {0}"
    LOG_SEND_FORMAT = "Received: {0}"
    DEFAULT_TEST_CASE_ID = "DefaultTestCase"

    def __init__(self, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        :param file_handle: Open file handle for logging. Defaults to sys.stdout.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str

    def open_test_step(self, description):
        self._print_log_msg(self.TEST_STEP_FORMAT.format(description))

    def log_check(self, description):
        self._print_log_msg(self.LOG_CHECK_FORMAT.format(description))

    def log_recv(self, data):
        self._print_log_msg(self.LOG_RECV_FORMAT.format(self._format_raw_bytes(data)))

    def log_send(self, data):
        self._print_log_msg(self.LOG_SEND_FORMAT.format(self._format_raw_bytes(data)))

    def log_info(self, description):
        self._print_log_msg(self.LOG_INFO_FORMAT.format(description))

    def open_test_case(self, test_case_id):
        self._print_log_msg(self.TEST_CASE_FORMAT.format(test_case_id))

    def log_fail(self, description=""):
        self._print_log_msg(self.LOG_FAIL_FORMAT.format(description))

    def log_pass(self, description=""):
        self._print_log_msg(self.LOG_PASS_FORMAT.format(description))

    def _print_log_msg(self, msg):
        print(get_time_stamp() + ' ' + msg, file=self._file_handle)
