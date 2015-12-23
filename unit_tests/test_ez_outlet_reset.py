import unittest

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
        Then: urllib2.urlopen is called using the IP address with EzOutletReset.RESET_URL_PATH
         and: time.sleep is called
        """
        # mock_build_url.return_value('DEAD STRINGS TELL NO TALES')

        hostname = '12.34.56.78'
        dut_reset_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        e = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                  dut_reset_time=dut_reset_time,
                                                  timeout=timeout,
                                                  reset_delay=reset_delay)

        e.post_fail()

        mock_build_url.assert_called_once_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with('DEAD STRINGS TELL NO TALES', timeout=timeout)
        mock_time.sleep.assert_called_once_with(dut_reset_time + reset_delay)
