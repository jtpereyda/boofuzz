import unittest
# pytest is required as an extras_require:
# noinspection PyPackageRequirements
import mock
from boofuzz import fuzz_logger
from boofuzz import ifuzz_logger_backend


class TestFuzzLogger(unittest.TestCase):
    def setUp(self):
        self.mock_logger_1 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        self.mock_logger_2 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        self.logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self.mock_logger_1, self.mock_logger_2])

        self.some_text = "Some test text"
        self.some_other_text = "More test text"
        self.some_int = 1
        self.some_data = bytes('1234567890\0')

    def test_open_test_step(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling open_test_step() with some text.
        Then: open_test_step() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.open_test_step(description=self.some_text)

        self.mock_logger_1.open_test_step.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.open_test_step.assert_called_once_with(description=self.some_text)

    def test_log_error(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_error() with some text.
        Then: log_error() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.log_error(description=self.some_text)

        self.mock_logger_1.log_error.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.log_error.assert_called_once_with(description=self.some_text)

    def test_log_fail(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_fail() with some text.
        Then: log_fail() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.log_fail(description=self.some_text)

        self.mock_logger_1.log_fail.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.log_fail.assert_called_once_with(description=self.some_text)

    def test_log_info(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_info() with some text.
        Then: log_info() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.log_info(description=self.some_text)

        self.mock_logger_1.log_info.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.log_info.assert_called_once_with(description=self.some_text)

    def test_log_recv(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_recv() with some data.
        Then: log_recv() is called with that same data on each
              IFuzzLoggerBackend.
        """
        self.logger.log_recv(data=self.some_data)

        self.mock_logger_1.log_recv.assert_called_once_with(data=self.some_data)
        self.mock_logger_2.log_recv.assert_called_once_with(data=self.some_data)

    def test_log_pass(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_pass() with some text.
        Then: test_log_pass() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.log_pass(description=self.some_text)

        self.mock_logger_1.log_pass.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.log_pass.assert_called_once_with(description=self.some_text)

    def test_log_check(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_check() with some text.
        Then: log_check() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.log_check(description=self.some_text)

        self.mock_logger_1.log_check.assert_called_once_with(description=self.some_text)
        self.mock_logger_2.log_check.assert_called_once_with(description=self.some_text)

    def test_open_test_case(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling open_test_case() with some text.
        Then: open_test_case() is called with that same text on each
              IFuzzLoggerBackend.
        """
        self.logger.open_test_case(test_case_id=self.some_text, name=self.some_other_text, index=self.some_int)

        self.mock_logger_1.open_test_case.assert_called_once_with(test_case_id=self.some_text,
                                                                  name=self.some_other_text,
                                                                  index=self.some_int)
        self.mock_logger_2.open_test_case.assert_called_once_with(test_case_id=self.some_text,
                                                                  name=self.some_other_text,
                                                                  index=self.some_int)

    def test_log_send(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling log_send() with some data.
        Then: log_send() is called with that same data on each
              IFuzzLoggerBackend.
        """
        self.logger.log_send(data=self.some_data)

        self.mock_logger_1.log_send.assert_called_once_with(data=self.some_data)
        self.mock_logger_2.log_send.assert_called_once_with(data=self.some_data)

    def test_failure_count(self):
        """
        Given: A FuzzLogger.
        When: Calling open_test_case
         and: log_fail three times
         and: open_test_case
         and: log_fail once.
        Then: failed_test_cases contains no failed test case info at first.
         and: failed_test_cases contains information from each log_fail,
              indexed by the opened test case, as each failure is added.
         and: len(passed_test_cases) == 0
         and: len(error_test_cases) == 0
        """
        self.assertEqual(0, len(self.logger.failed_test_cases))

        self.logger.open_test_case(test_case_id='!@#$%^&*()', name=self.some_other_text, index=self.some_int)
        self.logger.log_fail('FAILURE 1')
        self.assertEqual(['FAILURE 1'], self.logger.failed_test_cases['!@#$%^&*()'])

        self.logger.open_test_case(test_case_id='haiku', name=self.some_other_text, index=self.some_int)
        self.logger.log_fail('010')
        self.logger.log_fail('11001')
        self.logger.log_fail('1110')
        self.assertEqual(['010', '11001', '1110'], self.logger.failed_test_cases['haiku'])

        self.assertEqual(0, len(self.logger.passed_test_cases))
        self.assertEqual(0, len(self.logger.error_test_cases))

    def test_error_count(self):
        """
        Given: A FuzzLogger.
        When: Calling open_test_case
         and: log_error three times
         and: open_test_case
         and: log_error once.
        Then: error_test_cases contains no test error info at first.
         and: error_test_cases contains information from each log_error,
              indexed by the opened test case, as each error is added.
         and: len(passed_test_cases) == 0
         and: len(failed_test_cases) == 0
        """
        self.assertEqual(0, len(self.logger.error_test_cases))

        self.logger.open_test_case(test_case_id='a', name=self.some_other_text, index=self.some_int)
        self.logger.log_error('FAILURE 1')
        self.assertEqual(['FAILURE 1'], self.logger.error_test_cases['a'])

        # Use a number to verify that non-string keys can work
        self.logger.open_test_case(test_case_id=5, name=self.some_other_text, index=self.some_int)

        line1 = 'Sit here and rot, high, fat, all day, you boys,'
        line2 = 'Far lengths hide pain, mother\'s sobs, children\'s bones'
        line3 = 'New race, new hope, new day, my weed is gone.'
        self.logger.log_error(line1)
        self.logger.log_error(line2)
        self.logger.log_error(line3)
        self.assertEqual([line1, line2, line3], self.logger.error_test_cases[5])

        self.assertEqual(0, len(self.logger.passed_test_cases))
        self.assertEqual(0, len(self.logger.failed_test_cases))

    def test_pass_count(self):
        """
        Given: A FuzzLogger.
        When: Calling open_test_case
         and: log_pass three times
         and: open_test_case
         and: log_pass once.
        Then: passed_test_cases contains no test cases at first.
         and: passed_test_cases contains information from each log_pass,
              indexed by the opened test case, as each pass is added.
         and: len(failed_test_cases) == 0
         and: len(error_test_cases) == 0
        """
        self.assertEqual(0, len(self.logger.passed_test_cases))

        self.logger.open_test_case(test_case_id='a', name=self.some_other_text, index=self.some_int)
        self.logger.log_pass('Good to go')
        self.assertEqual(['Good to go'], self.logger.passed_test_cases['a'])

        self.logger.open_test_case(test_case_id=-1, name=self.some_other_text, index=self.some_int)

        line1 = 'Yes'
        line2 = 'Yes'
        line3 = 'I mean it!'
        self.logger.log_pass(line1)
        self.logger.log_pass(line2)
        self.logger.log_pass(line3)
        self.assertEqual([line1, line2, line3], self.logger.passed_test_cases[-1])

        self.assertEqual(0, len(self.logger.failed_test_cases))
        self.assertEqual(0, len(self.logger.error_test_cases))

    def test_all_test_cases_array(self):
        """
        Given: A FuzzLogger.
        When: Calling open_test_case
         and: open_test_case again
         and: log_pass
         and: open_test_case
         and: log_fail
         and: open_test_case
         and: log_error
        Then: all_test_cases contains no test cases at first.
         and: all_test_cases contains each opened test case, as each is added.
        """
        self.assertEqual([], self.logger.all_test_cases)

        self.logger.open_test_case(test_case_id='a', name=self.some_other_text, index=self.some_int)
        self.assertEqual(['a'], self.logger.all_test_cases)

        self.logger.open_test_case(test_case_id='b', name=self.some_other_text, index=self.some_int)
        self.logger.log_pass()
        self.assertEqual(['a', 'b'], self.logger.all_test_cases)

        self.logger.open_test_case(test_case_id='c', name=self.some_other_text, index=self.some_int)
        self.logger.log_fail()
        self.assertEqual(['a', 'b', 'c'], self.logger.all_test_cases)

        self.logger.open_test_case(test_case_id='d', name=self.some_other_text, index=self.some_int)
        self.logger.log_error(description='uh oh!')
        self.assertEqual(['a', 'b', 'c', 'd'], self.logger.all_test_cases)


if __name__ == '__main__':
    unittest.main()
