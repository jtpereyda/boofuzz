from __future__ import print_function
import sys
from colorama import Fore, Back, Style, init

from . import helpers
from . import ifuzz_logger_backend

init()

DEFAULT_HEX_TO_STR = helpers.hex_to_hexstr


class FuzzLoggerText(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for text presentation. It can be
    configured to output to STDOUT, or to a named file.

    Using two FuzzLoggerTexts, a FuzzLogger instance can be configured to output to
    both console and file.
    """
    TEST_CASE_FORMAT = Fore.YELLOW + Style.BRIGHT + "Test Case: {0}" + Style.RESET_ALL
    TEST_STEP_FORMAT = Fore.MAGENTA + Style.BRIGHT + "Test Step: {0}" + Style.RESET_ALL
    LOG_ERROR_FORMAT = Back.RED + Style.BRIGHT + "Error!!!! {0}" + Style.RESET_ALL
    LOG_CHECK_FORMAT = "Check: {0}"
    LOG_INFO_FORMAT = "Info: {0}"
    LOG_PASS_FORMAT = Fore.GREEN + Style.BRIGHT + "Check OK: {0}" + Style.RESET_ALL
    LOG_FAIL_FORMAT = Fore.RED + Style.BRIGHT + "Check Failed: {0}" + Style.RESET_ALL
    LOG_RECV_FORMAT = Fore.CYAN + "Received: {0}" + Style.RESET_ALL
    LOG_SEND_FORMAT = Fore.CYAN + "Transmitting {0} bytes: {1}" + Style.RESET_ALL
    DEFAULT_TEST_CASE_ID = "DefaultTestCase"
    INDENT_SIZE = 2

    def __init__(self, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        :type file_handle: io.FileIO
        :param file_handle: Open file handle for logging. Defaults to sys.stdout.

        :type bytes_to_str: function
        :param bytes_to_str: Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str

    def open_test_step(self, description):
        self._print_log_msg(self.TEST_STEP_FORMAT.format(description),
                            msg_type='step')

    def log_check(self, description):
        self._print_log_msg(self.LOG_CHECK_FORMAT.format(description),
                            msg_type='check')

    def log_error(self, description):
        self._print_log_msg(self.LOG_ERROR_FORMAT.format(description),
                            msg_type='error')

    def log_recv(self, data):
        self._print_log_msg(self.LOG_RECV_FORMAT.format(self._format_raw_bytes(data)),
                            msg_type='receive')

    def log_send(self, data):
        self._print_log_msg(
            self.LOG_SEND_FORMAT.format(len(data), self._format_raw_bytes(data)),
            msg_type='send')

    def log_info(self, description):
        self._print_log_msg(self.LOG_INFO_FORMAT.format(description),
                            msg_type='info')

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._print_log_msg(self.TEST_CASE_FORMAT.format(test_case_id),
                            msg_type='test_case')

    def log_fail(self, description=""):
        self._print_log_msg(self.LOG_FAIL_FORMAT.format(description),
                            msg_type='fail')

    def log_pass(self, description=""):
        self._print_log_msg(self.LOG_PASS_FORMAT.format(description),
                            msg_type='pass')

    def _print_log_msg(self, msg, msg_type):
        print(helpers.format_log_msg(msg_type=msg_type, description=msg, indent_size=self.INDENT_SIZE),
              file=self._file_handle)
