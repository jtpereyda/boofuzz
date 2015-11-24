import collections
import ifuzz_logger


class FuzzLogger(ifuzz_logger.IFuzzLogger):
    """
    Implementation for IFuzzLogger.

    FuzzLogger takes logged data and directs it to the appropriate backends.
    It aggregates an arbitrary number of logger backends, and functions like a
    multiplexer.

    FuzzLogger also maintains failure and error data.
    """
    def __init__(self, fuzz_loggers=None):
        if fuzz_loggers is None:
            fuzz_loggers = []
        self._fuzz_loggers = fuzz_loggers

        self._cur_test_case_id = ''
        self.failed_test_cases = collections.defaultdict(list)
        self.error_test_cases = collections.defaultdict(list)

    def open_test_step(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.open_test_step(description=description)

    def log_error(self, description):
        self.error_test_cases[self._cur_test_case_id].append(description)
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_error(description=description)

    def log_fail(self, description=""):
        self.failed_test_cases[self._cur_test_case_id].append(description)
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_fail(description=description)

    def log_info(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_info(description=description)

    def log_recv(self, data):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_recv(data=data)

    def log_pass(self, description=""):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_pass(description=description)

    def log_check(self, description):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_check(description=description)

    def open_test_case(self, test_case_id):
        self._cur_test_case_id = test_case_id
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.open_test_case(test_case_id=test_case_id)

    def log_send(self, data):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.log_send(data=data)
