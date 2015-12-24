import unittest
import urllib2

try:
    import unittest.mock as mock
except ImportError:
    # mock is required as an extras_require:
    # noinspection PyPackageRequirements
    import mock

import boofuzz


class TestEzOutletReset(unittest.TestCase):
    """
    EzOutletReset.post_fail is basically all side-effects, so its test is
    rather heavy in mocks.
    """
    sample_url = 'DEAD STRINGS TELL NO TALES'
    sample_response_contents = 'SAMPLE RESPONSE'

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_build_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail(self, mock_time, mock_urllib2, mock_build_url):
        """
        Given: EzOutletReset initialized with an IP address, dut_reset_time, timeout, and reset_delay.
        When: Calling post_fail().
        Then: ez_outlet_reset._build_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen is called using ez_outlet_reset._build_url's result with timeout.
         and: time.sleep(dut_reset_time + reset_delay) is called.
        """
        # Given
        hostname = '12.34.56.78'
        dut_reset_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        e = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                  dut_reset_time=dut_reset_time,
                                                  timeout=timeout,
                                                  reset_delay=reset_delay)

        # When
        e.post_fail()

        # Then
        mock_build_url.assert_called_once_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_time.sleep.assert_called_once_with(dut_reset_time + reset_delay)

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_build_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail_with_logger(self, mock_time, mock_urllib2, mock_build_url):
        """
        Given: Mock urllib2 configured such that
              urlopen returns a mock whose read() method returns sample_response_contents.
          and: EzOutletReset initialized with an IP address, dut_reset_time, timeout, and reset_delay.
        When: Calling post_fail() with a mock_logger.
        Then: ez_outlet_reset._build_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: mock_logger.log_info(EzOutletReset.LOG_REQUEST_MSG.format(sample_url)) is called
              where sample_rul is ez_outlet_reset._build_url's result.
         and: urllib2.urlopen is called using ez_outlet_reset._build_url's result with timeout.
         and: mock_logger.log_recv() is called with sample_response_contents.
         and: time.sleep(dut_reset_time + reset_delay) is called.
        """
        # Given
        mock_urllib2.configure_mock(
                **{'urlopen.return_value': mock.MagicMock(
                        **{'read.return_value': self.sample_response_contents})})
        hostname = '12.34.56.78'
        dut_reset_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        e = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                  dut_reset_time=dut_reset_time,
                                                  timeout=timeout,
                                                  reset_delay=reset_delay)

        # When
        mock_logger = mock.MagicMock()
        e.post_fail(logger=mock_logger)

        # Then
        mock_logger.log_info.assert_called_once_with(
            boofuzz.ez_outlet_reset.EzOutletReset.LOG_REQUEST_MSG.format(self.sample_url))
        mock_build_url.assert_called_once_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_logger.log_recv.assert_called_once_with(self.sample_response_contents)
        mock_time.sleep.assert_called_once_with(dut_reset_time + reset_delay)

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_build_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail_error(self, mock_time, mock_urllib2, mock_build_url):
        """
        Given: Mock urllib2 configured to raise urllib2.URLError on urlopen.
          and: EzOutletReset initialized with an IP address, dut_reset_time, timeout, and reset_delay.
        When: Calling post_fail() with a mock_logger.
        Then: post_fail() raises boofuzz.sex.SullyRuntimeError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: mock_logger.log_info() is called in this order with these parameters:
               1. EzOutletReset.LOG_REQUEST_MSG.format(sample_url)
                  where sample_rul is ez_outlet_reset._build_url's result.
               2. EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: ez_outlet_reset._build_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen is called using ez_outlet_reset._build_url's result with timeout.
         and: mock_logger.log_recv() is _not_ called
         and: time.sleep(dut_reset_time + reset_delay) is _not_ called.
        """
        # Given
        mock_urllib2.configure_mock(**{'urlopen.side_effect': urllib2.URLError("Dummy reason")})
        mock_urllib2.URLError = urllib2.URLError  # Restore mocked-away URLError
        # and
        hostname = '12.34.56.78'
        dut_reset_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        ez = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                   dut_reset_time=dut_reset_time,
                                                   timeout=timeout,
                                                   reset_delay=reset_delay)

        # When
        mock_logger = mock.MagicMock()
        with self.assertRaises(boofuzz.sex.SullyRuntimeError) as e:
            ez.post_fail(logger=mock_logger)

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout))
        mock_logger.log_info.assert_has_calls([
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.LOG_REQUEST_MSG.format(self.sample_url)),
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout)),
            ]
        )
        mock_build_url.assert_called_once_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_logger.log_recv.assert_not_called()
        mock_time.sleep.assert_not_called()
