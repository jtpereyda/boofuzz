from __future__ import print_function
from sulley import ifuzz_logger
import sys


class FuzzLoggerText(ifuzz_logger.IFuzzLogger):
    def __init__(self, file_handle=sys.stdout):
        """
        :param file_handle: Open file handle for logging. Defaults to sys.stdout.
        """
        pass

    def open_test_step(self, description):
        pass

    def log_check(self, description):
        pass

    def log_recv(self, data):
        pass

    def log_send(self, data):
        pass

    def log_info(self, description):
        pass

    def open_test_case(self, test_case_id):
        pass

    def log_fail(self, description=""):
        pass

    def log_pass(self, description=""):
        pass
