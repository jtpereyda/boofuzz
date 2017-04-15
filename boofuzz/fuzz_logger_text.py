from __future__ import print_function
from builtins import bytes
import sys
import time
from colorama import Fore, Back, Style, init

from . import helpers
from . import ifuzz_logger_backend

init()

def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    @param input_bytes: Arbitrary bytes.

    @return: Printable string.
    """
    return helpers.hex_str(input_bytes) + " " + repr(bytes(input_bytes))


DEFAULT_HEX_TO_STR = hex_to_hexstr


def get_time_stamp():
    t = time.time()
    s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(t))
    s += ",%03d]" % (t * 1000 % 1000)
    return s


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
        @type file_handle: io.FileIO
        @param file_handle: Open file handle for logging. Defaults to sys.stdout.

        @type bytes_to_str: function
        @param bytes_to_str: Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str

    def open_test_step(self, description):
        self._print_log_msg(self.TEST_STEP_FORMAT.format(description),
                            indent_level=1)

    def log_check(self, description):
        self._print_log_msg(self.LOG_CHECK_FORMAT.format(description),
                            indent_level=2)

    def log_error(self, description):
        self._print_log_msg(self.LOG_ERROR_FORMAT.format(description),
                            indent_level=2)

    def log_recv(self, data):
        self._print_log_msg(self.LOG_RECV_FORMAT.format(self._format_raw_bytes(data)),
                            indent_level=2)

    def log_send(self, data):
        self._print_log_msg(
            self.LOG_SEND_FORMAT.format(len(data), self._format_raw_bytes(data)),
            indent_level=2)

    def log_info(self, description):
        self._print_log_msg(self.LOG_INFO_FORMAT.format(description),
                            indent_level=2)

    def open_test_case(self, test_case_id):
        self._print_log_msg(self.TEST_CASE_FORMAT.format(test_case_id),
                            indent_level=0)

    def log_fail(self, description=""):
        self._print_log_msg(self.LOG_FAIL_FORMAT.format(description),
                            indent_level=3)

    def log_pass(self, description=""):
        self._print_log_msg(self.LOG_PASS_FORMAT.format(description),
                            indent_level=3)

    def _print_log_msg(self, msg, indent_level=0):
        msg = _indent_all_lines(msg, indent_level * self.INDENT_SIZE)
        time_stamp = get_time_stamp()
        print(time_stamp + ' ' + _indent_after_first_line(msg, len(time_stamp) + 1), file=self._file_handle)


def _indent_all_lines(lines, amount, ch=' '):
    padding = amount * ch
    return padding + ('\n' + padding).join(lines.split('\n'))


def _indent_after_first_line(lines, amount, ch=' '):
    padding = amount * ch
    return ('\n' + padding).join(lines.split('\n'))
