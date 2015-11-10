import unittest


class TestFuzzLogger(unittest.TestCase):
    def test_open_test_step(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling open_test_step().
        Then: open_test_step() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_log_fail(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling open_test_step().
        Then: open_test_step() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_log_info(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_info().
        Then: test_log_info() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_log_recv(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_recv().
        Then: test_log_recv() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_log_pass(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_pass().
        Then: test_log_pass() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_log_check(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_check().
        Then: test_log_check() is called on each IFuzzLoggerBackend.
        """
        pass

    def test_open_test_case(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_open_test_case().
        Then: test_open_test_case() is called on each IFuzzLoggerBackend.
        """

    def test_log_send(self):
        """
        Given: A FuzzLogger with multiple IFuzzLoggerBackends.
        When: Calling test_log_send().
        Then: test_log_send() is called on each IFuzzLoggerBackend.
        """
        pass

if __name__ == '__main__':
    unittest.main()
