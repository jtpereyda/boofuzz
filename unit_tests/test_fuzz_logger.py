import unittest
import mock
from sulley import fuzz_logger
from sulley import ifuzz_logger_backend


class TestFuzzLogger(unittest.TestCase):
    def setUp(self):
        self.mock_logger_1 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        self.mock_logger_2 = mock.MagicMock(spec=ifuzz_logger_backend.IFuzzLoggerBackend)
        self.logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self.mock_logger_1, self.mock_logger_2])

        self.some_text = "Some test text"
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
        self.logger.open_test_case(test_case_id=self.some_text)

        self.mock_logger_1.open_test_case.assert_called_once_with(test_case_id=self.some_text)
        self.mock_logger_2.open_test_case.assert_called_once_with(test_case_id=self.some_text)

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


if __name__ == '__main__':
    unittest.main()
