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
        self._print_log_msg(msg=description,
                            msg_type='step')

    def log_check(self, description):
        self._print_log_msg(msg=description,
                            msg_type='check')

    def log_error(self, description):
        self._print_log_msg(msg=description,
                            msg_type='error')

    def log_recv(self, data):
        self._print_log_msg(data=data,
                            msg_type='receive')

    def log_send(self, data):
        self._print_log_msg(
            data=data,
            msg_type='send')

    def log_info(self, description):
        self._print_log_msg(msg=description,
                            msg_type='info')

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._print_log_msg(msg=test_case_id,
                            msg_type='test_case')

    def log_fail(self, description=""):
        self._print_log_msg(msg=description,
                            msg_type='fail')

    def log_pass(self, description=""):
        self._print_log_msg(msg=description,
                            msg_type='pass')

    def _print_log_msg(self, msg_type, msg=None, data=None):
        print(helpers.format_log_msg(msg_type=msg_type, description=msg, data=data, indent_size=self.INDENT_SIZE),
              file=self._file_handle)
