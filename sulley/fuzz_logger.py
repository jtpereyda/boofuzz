from sulley import ifuzz_logger


class FuzzLogger(ifuzz_logger.IFuzzLogger):
    def __init__(self, fuzz_loggers=None):
        if fuzz_loggers is None:
            fuzz_loggers = []
        self._fuzz_loggers = fuzz_loggers

    def open_test_step(self, description):
        pass

    def log_fail(self, description=""):
        pass

    def log_info(self, description):
        pass

    def log_recv(self, data):
        pass

    def log_pass(self, description=""):
        pass

    def log_check(self, description):
        pass

    def open_test_case(self, test_case_id):
        for fuzz_logger in self._fuzz_loggers:
            fuzz_logger.open_test_case(test_case_id=test_case_id)

    def log_send(self, data):
        pass
