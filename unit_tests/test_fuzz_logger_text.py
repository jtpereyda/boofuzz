import unittest
import io
import os
from sulley import fuzz_logger_text

LOGGER_PREAMBLE = ".*"
TEST_CASE_FORMAT = LOGGER_PREAMBLE + "Test Case: {0}" + os.linesep
TEST_STEP_FORMAT = LOGGER_PREAMBLE + "Test Step: {0}" + os.linesep
LOG_CHECK_FORMAT = LOGGER_PREAMBLE + "Check: {0}" + os.linesep
LOG_INFO_FORMAT = LOGGER_PREAMBLE + "Info: {0}" + os.linesep
LOG_PASS_FORMAT = LOGGER_PREAMBLE + "Check OK {0}" + os.linesep
LOG_FAIL_FORMAT = LOGGER_PREAMBLE + "Check Failed {0}" + os.linesep
LOG_RECV_FORMAT = LOGGER_PREAMBLE + "Transmitting: {0}" + os.linesep
LOG_SEND_FORMAT = LOGGER_PREAMBLE + "Received: {0}" + os.linesep
DEFAULT_TEST_CASE_ID = "DefaultTestCase"


class TestFuzzLoggerText(unittest.TestCase):

    def setUp(self):
        self.virtual_file = io.StringIO()
        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file)
        self.some_test_case_id = "some test case"
        self.some_test_step_msg = "Test!!!"
        self.some_log_check_msg = "logging"
        self.some_log_info_msg = "information"
        self.some_log_fail_msg = "broken"
        self.some_log_pass_msg = "it works so far!"

    def test_open_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
        Then: open_test_case logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))

    def test_open_test_step(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
        Then: open_test_case logs as expected.
         and: open_test_step logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.open_test_step(self.some_test_step_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_STEP_FORMAT.format(self.some_test_step_msg))

    def test_log_check(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with some description.
        Then: open_test_case logs as expected.
         and: log_check logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_check(self.some_log_check_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_CHECK_FORMAT.format(self.some_log_check_msg))

    def test_log_recv(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_recv(bytes('A B C'))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format('41 20 42 20 43'))

    def test_log_send(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with some data.
        Then: open_test_case logs as expected.
         and: log_send logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_send(bytes('123'))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format('31 32 33'))

    def test_log_info(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with some description.
        Then: open_test_case logs as expected.
         and: log_info logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_info(self.some_log_info_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_INFO_FORMAT.format(self.some_log_info_msg))

    def test_log_fail(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with some description.
        Then: open_test_case logs as expected.
         and: log_fail logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_fail(self.some_log_fail_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_FAIL_FORMAT.format(self.some_log_fail_msg))

    def test_log_pass(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with some description.
        Then: open_test_case logs as expected.
         and: log_pass logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_pass(self.some_log_pass_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_PASS_FORMAT.format(self.some_log_pass_msg))

    def test_open_test_case_empty(self,):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with an empty string.
        Then: open_test_case logs with a zero-length test case id.
        """
        # When
        self.logger.open_test_case('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(''))

    def test_open_test_step_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with an empty string.
        Then: open_test_step logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.open_test_step('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_STEP_FORMAT.format(''))

    def test_log_check_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with an empty string.
        Then: log_check logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_check('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_CHECK_FORMAT.format(''))

    def test_log_recv_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with an empty buffer.
        Then: log_recv logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_recv(bytes(''))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format(''))

    def test_log_send_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with an empty buffer.
        Then: log_send logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_send(bytes(''))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format(''))

    def test_log_info_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with an empty string.
        Then: log_info logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_info('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_INFO_FORMAT.format(''))

    def test_log_fail_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with no argument.
        Then: log_fail logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_fail('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_FAIL_FORMAT.format(''))

    def test_log_pass_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with no argument.
        Then: log_pass logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_pass('')

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_PASS_FORMAT.format(''))

    def test_open_test_step_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_step with some description.
        Then: A default test case is opened.
         and: open_test_step logs as expected.
        """
        # When
        self.logger.open_test_step(self.some_test_step_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_STEP_FORMAT.format(self.some_test_step_msg))

    def test_log_check_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_check with some description.
        Then: A default test case is opened.
         and: log_check logs as expected.
        """
        # When
        self.logger.log_check(self.some_log_check_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_CHECK_FORMAT.format(self.some_log_check_msg))

    def test_log_recv_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_recv with some data.
        Then: A default test case is opened.
         and: log_recv logs as expected.
        """
        # When
        self.logger.log_recv(bytes('A B C'))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format('41 20 42 20 43'))

    def test_log_send_no_test_case_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_send with some data.
        Then: A default test case is opened.
         and: log_send logs as expected.
        """
        # When
        self.logger.log_send(bytes('123'))

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format('31 32 33'))

    def test_log_info_no_test_case_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_info with some description.
        Then: A default test case is opened.
         and: log_info logs as expected.
        """
        # When
        self.logger.log_info(self.some_log_info_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_INFO_FORMAT.format(self.some_log_info_msg))

    def test_log_fail_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_fail with some description.
        Then: A default test case is opened.
         and: log_fail logs as expected.
        """
        # When
        self.logger.log_fail(self.some_log_fail_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_FAIL_FORMAT.format(self.some_log_fail_msg))

    def test_log_pass_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_pass with some description.
        Then: A default test case is opened.
         and: log_pass logs as expected.
        """
        # When
        self.logger.log_pass(self.some_log_pass_msg)

        # Then
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_PASS_FORMAT.format(self.some_log_pass_msg))

    def test_several(self):
        """
        Verify that log functions work consistently in series.

        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
         and: Calling log_check with some description.
         and: Calling log_recv with some data.
         and: Calling log_send with some data.
         and: Calling log_info with some description.
         and: Calling log_fail with some description.
         and: Calling log_pass with some description.
        Then: All methods log as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.open_test_step(self.some_test_step_msg)
        self.logger.log_check(self.some_log_check_msg)
        self.logger.log_recv(bytes('AB'))
        self.logger.log_send(bytes('CD'))
        self.logger.log_info(self.some_log_info_msg)
        self.logger.log_fail(self.some_log_fail_msg)
        self.logger.log_pass(self.some_log_pass_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_STEP_FORMAT.format(self.some_test_step_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_CHECK_FORMAT.format(self.some_log_check_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format('40 41'))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format('42 43'))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_INFO_FORMAT.format(self.some_log_info_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_FAIL_FORMAT.format(self.some_log_fail_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_PASS_FORMAT.format(self.some_log_pass_msg))

    # TODO: Add tests differentiating colors.

if __name__ == '__main__':
    unittest.main()
