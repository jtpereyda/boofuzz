import unittest
import StringIO
import os
from sulley import fuzz_logger_text

LOGGER_PREAMBLE = ".*"
TEST_CASE_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.TEST_CASE_FORMAT + os.linesep
TEST_STEP_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.TEST_STEP_FORMAT + os.linesep
LOG_CHECK_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_CHECK_FORMAT + os.linesep
LOG_INFO_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_INFO_FORMAT + os.linesep
LOG_PASS_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_PASS_FORMAT + os.linesep
LOG_FAIL_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_FAIL_FORMAT + os.linesep
LOG_RECV_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_RECV_FORMAT + os.linesep
LOG_SEND_FORMAT = LOGGER_PREAMBLE + fuzz_logger_text.FuzzLoggerText.LOG_SEND_FORMAT + os.linesep
DEFAULT_TEST_CASE_ID = fuzz_logger_text.FuzzLoggerText.DEFAULT_TEST_CASE_ID


class TestFuzzLoggerTextFreeFunctions(unittest.TestCase):
    def test_get_time_stamp(self):
        """
        Given: No context.
        When: Calling get_time_stamp().
        Then: get_time_stamp() returns time stamp in proper format.
        """
        # When
        s = fuzz_logger_text.get_time_stamp()

        # Then
        self.assertRegexpMatches(s, '\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d\d\d\]')


class TestFuzzLoggerText(unittest.TestCase):

    def setUp(self):
        self.virtual_file = StringIO.StringIO()
        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file)
        self.some_test_case_id = "some test case"
        self.some_test_step_msg = "Test!!!"
        self.some_log_check_msg = "logging"
        self.some_log_info_msg = "information"
        self.some_log_fail_msg = "broken"
        self.some_log_pass_msg = "it works so far!"
        self.some_recv_data = bytes('A B C')
        self.some_send_data = bytes('123')

    def test_open_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
        Then: open_test_case logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id)

        # Then
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_recv_data)))

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
        self.logger.log_send(self.some_send_data)

        # Then
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_recv_data)))

    def test_log_send_no_test_case_no_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling log_send with some data.
        Then: A default test case is opened.
         and: log_send logs as expected.
        """
        # When
        self.logger.log_send(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(DEFAULT_TEST_CASE_ID))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_recv_data)))

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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.virtual_file.seek(0)
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
        self.logger.log_recv(self.some_recv_data)
        self.logger.log_send(self.some_send_data)
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
                                 LOG_RECV_FORMAT.format(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_recv_data)))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_SEND_FORMAT.format(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_send_data)))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_INFO_FORMAT.format(self.some_log_info_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_FAIL_FORMAT.format(self.some_log_fail_msg))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_PASS_FORMAT.format(self.some_log_pass_msg))

    def test_hex_to_str_function(self):
        """
        Verify that the UUT uses the custom hex_to_str function, if provided.

        Given: FuzzLoggerText with a virtual file handle and custom hex_to_str
               function.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected, using the custom hex_to_str function.
        """
        # Given
        def hex_to_str(hex_data):
            return hex_data.decode()

        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file,
                                                      bytes_to_str=hex_to_str)
        # When
        self.logger.open_test_case(self.some_test_case_id)
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 TEST_CASE_FORMAT.format(self.some_test_case_id))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOG_RECV_FORMAT.format(hex_to_str(self.some_recv_data)))


if __name__ == '__main__':
    unittest.main()
