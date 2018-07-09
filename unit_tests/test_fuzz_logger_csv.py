import unittest
import re
import StringIO
from boofuzz import fuzz_logger_csv

LOGGER_PREAMBLE = ".*,"


class TestFuzzLoggerCsvFreeFunctions(unittest.TestCase):
    def test_get_time_stamp(self):
        """
        Given: No context.
        When: Calling get_time_stamp().
        Then: get_time_stamp() returns time stamp in proper format.
        """
        # When
        s = fuzz_logger_csv.get_time_stamp()

        # Then
        self.assertRegexpMatches(s, '\d\d\d\d-\d\d-\d\d\w\d\d:\d\d:\d\d.\d*')

    def test_hex_to_hexstr(self):
        """
        Given: A set of bytes representing a string with several lines.
        When: Calling hex_to_hexstr
        Then: Hex of several-line string is output first, then repr format.
        """
        given = "abc\n123\r\nA\n"
        expected = u'61 62 63 0a 31 32 33 0d 0a 41 0a'
        self.assertEqual(expected, fuzz_logger_csv.hex_to_hexstr(given))


class TestFuzzLoggerCsv(unittest.TestCase):
    def setUp(self):
        self.virtual_file = StringIO.StringIO()
        self.logger = fuzz_logger_csv.FuzzLoggerCsv(file_handle=self.virtual_file)
        self.some_test_case_id = "some test case"
        self.some_test_case_name = "some test case name"
        self.some_test_case_index = 3
        self.some_test_step_msg = "Test!!!"
        self.some_log_check_msg = "logging"
        self.some_log_info_msg = "information"
        self.some_log_fail_msg = "broken"
        self.some_log_pass_msg = "it works so far!"
        self.some_log_error_msg = "D:"
        self.some_recv_data = bytes('A B C')
        self.some_send_data = bytes('123')

    def test_open_test_case(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
        Then: open_test_case logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))

    def test_open_test_step(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
        Then: open_test_case logs as expected.
         and: open_test_step logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.open_test_step(self.some_test_step_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("open step,,," + self.some_test_step_msg + "\r\n"))

    def test_log_check(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with some description.
        Then: open_test_case logs as expected.
         and: log_check logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_check(self.some_log_check_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("check,,," + self.some_log_check_msg + "\r\n"))

    def test_log_error(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_error with some description.
        Then: open_test_case logs as expected.
         and: log_error logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_error(self.some_log_error_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("error,,," + self.some_log_error_msg + "\r\n"))

    def test_log_recv(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "recv," + str(len(self.some_recv_data)) + "," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(
                                         self.some_recv_data) + "," + self.some_recv_data + "\r\n"))

    def test_log_send(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with some data.
        Then: open_test_case logs as expected.
         and: log_send logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_send(self.some_send_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "send," + str(len(self.some_send_data)) + "," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(
                                         self.some_send_data) + "," + self.some_send_data + "\r\n"))

    def test_log_info(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with some description.
        Then: open_test_case logs as expected.
         and: log_info logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_info(self.some_log_info_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("info,,," + self.some_log_info_msg + "\r\n"))

    def test_log_fail(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with some description.
        Then: open_test_case logs as expected.
         and: log_fail logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_fail(self.some_log_fail_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("fail,,," + self.some_log_fail_msg + "\r\n"))

    def test_log_pass(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with some description.
        Then: open_test_case logs as expected.
         and: log_pass logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_pass(self.some_log_pass_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("pass,,," + self.some_log_pass_msg + "\r\n"))

    def test_open_test_case_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with an empty string.
        Then: open_test_case logs with a zero-length test case id.
        """
        # When
        self.logger.open_test_case('', name=self.some_test_case_name, index=self.some_test_case_index)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("open test case,,,Test case \r\n"))

    def test_open_test_step_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with an empty string.
        Then: open_test_step logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.open_test_step('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("open step,,,\r\n"))

    def test_log_check_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with an empty string.
        Then: log_check logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_check('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("check,,,\r\n"))

    def test_log_error_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_error with an empty string.
        Then: log_error logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_error('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("error,,,\r\n"))

    def test_log_recv_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with an empty buffer.
        Then: log_recv logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_recv(bytes(''))

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "recv,0," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(bytes('')) + ",\r\n"))

    def test_log_send_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with an empty buffer.
        Then: log_send logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_send(bytes(''))

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "send,0," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(bytes('')) + ",\r\n"))

    def test_log_info_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with an empty string.
        Then: log_info logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_info('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("info,,,\r\n"))

    def test_log_fail_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with no argument.
        Then: log_fail logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_fail('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("fail,,,\r\n"))

    def test_log_pass_empty(self):
        """
        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with no argument.
        Then: log_pass logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_pass('')

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("pass,,,\r\n"))

    def test_several(self):
        """
        Verify that log functions work consistently in series.

        Given: FuzzLoggerCsv with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
         and: Calling log_recv with some data.
         and: Calling log_send with some data.
         and: Calling log_info with some description.
         and: Calling log_check with some description.
         and: Calling log_fail with some description.
         and: Calling log_pass with some description.
         and: Calling log_error with some description.
        Then: All methods log as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.open_test_step(self.some_test_step_msg)
        self.logger.log_recv(self.some_recv_data)
        self.logger.log_send(self.some_send_data)
        self.logger.log_info(self.some_log_info_msg)
        self.logger.log_check(self.some_log_check_msg)
        self.logger.log_fail(self.some_log_fail_msg)
        self.logger.log_pass(self.some_log_pass_msg)
        self.logger.log_error(self.some_log_error_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("open step,,," + self.some_test_step_msg + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "recv," + str(len(self.some_recv_data)) + "," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(
                                         self.some_recv_data) + "," + self.some_recv_data + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "send," + str(len(self.some_send_data)) + "," + fuzz_logger_csv.DEFAULT_HEX_TO_STR(
                                         self.some_send_data) + "," + self.some_send_data + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("info,,," + self.some_log_info_msg + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("check,,," + self.some_log_check_msg + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("fail,,," + self.some_log_fail_msg + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("pass,,," + self.some_log_pass_msg + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape("error,,," + self.some_log_error_msg + "\r\n"))

    def test_hex_to_str_function(self):
        """
        Verify that the UUT uses the custom hex_to_str function, if provided.

        Given: FuzzLoggerCsv with a virtual file handle and custom hex_to_str
               function.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected, using the custom hex_to_str function.
        """

        # Given
        def hex_to_str(hex_data):
            return hex_data.decode()

        self.logger = fuzz_logger_csv.FuzzLoggerCsv(file_handle=self.virtual_file,
                                                    bytes_to_str=hex_to_str)
        # When
        self.logger.open_test_case(self.some_test_case_id,
                                   name=self.some_test_case_name,
                                   index=self.some_test_case_index)
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "open test case,,,Test case " + self.some_test_case_id + "\r\n"))
        self.assertRegexpMatches(self.virtual_file.readline(),
                                 LOGGER_PREAMBLE + re.escape(
                                     "recv," + str(len(self.some_recv_data)) + "," + hex_to_str(
                                         self.some_recv_data) + "," + self.some_recv_data + "\r\n"))


if __name__ == '__main__':
    unittest.main()
