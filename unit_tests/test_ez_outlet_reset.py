import unittest
import urllib2

try:
    import unittest.mock as mock
except ImportError:
    import mock

import boofuzz


class TestEzOutletReset(unittest.TestCase):
    @mock.patch.object(boofuzz.ez_outlet_reset, '_build_url', return_value='DEAD STRINGS TELL NO TALES')
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
        mock_urllib2.urlopen.assert_called_once_with('DEAD STRINGS TELL NO TALES', timeout=timeout)
        mock_time.sleep.assert_called_once_with(dut_reset_time + reset_delay)

    @mock.patch.object(boofuzz.ez_outlet_reset, '_build_url', return_value='DEAD STRINGS TELL NO TALES')
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail_error(self, mock_time, mock_urllib2, mock_build_url):
        """
        Given: Mock urllib2 configured to raise urllib2.URLError on urlopen.
          and: EzOutletReset initialized with an IP address, dut_reset_time, timeout, and reset_delay.
        When: Calling post_fail().
        Then: post_fail() raises a boofuzz.sex.SullyRuntimeError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: ez_outlet_reset._build_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen is called using ez_outlet_reset._build_url's result with timeout.
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
        with self.assertRaises(boofuzz.sex.SullyRuntimeError) as e:
            ez.post_fail()

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout))
        mock_build_url.assert_called_once_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with('DEAD STRINGS TELL NO TALES', timeout=timeout)
        mock_time.sleep.assert_not_called()
