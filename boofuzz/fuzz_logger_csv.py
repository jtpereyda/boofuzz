from __future__ import print_function
import sys
import datetime
import csv

from . import helpers
from . import ifuzz_logger_backend


def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    :param input_bytes: Arbitrary bytes.

    :return: Printable string.
    """
    return helpers.hex_str(input_bytes)


DEFAULT_HEX_TO_STR = hex_to_hexstr


def get_time_stamp():
    s = datetime.datetime.utcnow().isoformat()
    return s


class FuzzLoggerCsv(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for pcap file. It can be
    configured to output to a named file.
    """

    def __init__(self, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        Args:
            file_hanlde (io.TextIOBase): Open file handle for logging. Defaults to sys.stdout.
            bytes_to_str (function): Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str
        self._csv_handle = csv.writer(self._file_handle)

    def open_test_step(self, description):
        self._print_log_msg(["open step", "", "", description])

    def log_check(self, description):
        self._print_log_msg(["check", "", "", description])

    def log_error(self, description):
        self._print_log_msg(["error", "", "", description])

    def log_recv(self, data):
        self._print_log_msg(["recv", len(data), self._format_raw_bytes(data), data])

    def log_send(self, data):
        self._print_log_msg(["send", len(data), self._format_raw_bytes(data), data])

    def log_info(self, description):
        self._print_log_msg(["info", "", "", description])

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._print_log_msg(["open test case", "", "", "Test case " + str(test_case_id)])

    def log_fail(self, description=""):
        self._print_log_msg(["fail", "", "", description])

    def log_pass(self, description=""):
        self._print_log_msg(["pass", "", "", description])

    def _print_log_msg(self, msg):
        time_stamp = get_time_stamp()
        self._csv_handle.writerow([time_stamp] + msg)
