import unittest
import io
from sulley import fuzz_logger_text


class TestFuzzLoggerText(unittest.TestCase):

    def setUp(self):
        self.virtual_file = io.StringIO('virtual_test_file')
        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file)

    def test_open_test_case(self, test_case_id):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
        Then: open_test_case logs as expected.
        """
        pass

    def test_open_test_step(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
        Then: open_test_step logs as expected.
        """
        pass

    def test_log_check(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with some description.
        Then: log_check logs as expected.
        """
        pass

    def test_log_recv(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: log_recv logs as expected.
        """
        pass

    def test_log_send(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with some data.
        Then: log_send logs as expected.
        """
        pass

    def test_log_info(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with some description.
        Then: log_info logs as expected.
        """
        pass

    def test_log_fail(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with some description.
        Then: log_fail logs as expected.
        """
        pass

    def test_log_pass(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with some description.
        Then: log_pass logs as expected.
        """
        pass

    def test_open_test_case_empty(self, test_case_id):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with an empty string.
        Then: open_test_case logs with a zero-length test case id.
        """
        pass

    def test_open_test_step_empty(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with an empty string.
        Then: open_test_step logs with a zero-length description.
        """
        pass

    def test_log_check_empty(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with an empty string.
        Then: log_check logs with a zero-length description.
        """
        pass

    def test_log_recv_empty(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with an empty buffer.
        Then: log_recv logs with zero-length data.
        """
        pass

    def test_log_send_empty(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with an empty buffer.
        Then: log_send logs with zero-length data.
        """
        pass

    def test_log_info_empty(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with an empty string.
        Then: log_info logs with a zero-length description.
        """
        pass

    def test_log_fail_empty(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with no argument.
        Then: log_fail logs with a zero-length description.
        """
        pass

    def test_log_pass_empty(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with no argument.
        Then: log_pass logs with a zero-length description.
        """
        pass

    def test_open_test_step_no_test_case(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_step with some description.
        Then: A default test case is opened.
         and: open_test_step logs as expected.
        """
        pass

    def test_log_check_no_test_case(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_check with some description.
        Then: A default test case is opened.
         and: log_check logs as expected.
        """
        pass

    def test_log_recv_no_test_case(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_recv with some data.
        Then: A default test case is opened.
         and: log_recv logs as expected.
        """
        pass

    def test_log_send_no_test_case_no_test_case(self, data):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_send with some data.
        Then: A default test case is opened.
         and: log_send logs as expected.
        """
        pass

    def test_log_info_no_test_case_no_test_case(self, description):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_info with some description.
        Then: A default test case is opened.
         and: log_info logs as expected.
        """
        pass

    def test_log_fail_no_test_case(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_fail with some description.
        Then: A default test case is opened.
         and: log_fail logs as expected.
        """
        pass

    def test_log_pass_no_test_case(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_pass with some description.
        Then: A default test case is opened.
         and: log_pass logs as expected.
        """
        pass

    def test_several(self, description=""):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
         and: Calling log_check with some description.
         and: Calling log_recv with some data.
         and: Calling log_send with some data.
         and: Calling log_info with some description.
         and: Calling log_pass with some description.
        Then: log_pass logs with a zero-length description.
        """
        pass

    # TODO: Add tests differentiating colors.

if __name__ == '__main__':
    unittest.main()
