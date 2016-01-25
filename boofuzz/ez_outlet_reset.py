import sys
import time
import urllib2
import urlparse
import ifuzz_logger

import sex


def _get_url(hostname, path):
    return urlparse.urlunparse(('http', hostname, path, '', '', ''))


class EzOutletReset:
    """Uses ezOutlet EZ-11b to reset a device.

    Uses the ezOutlet EZ-11b Internet IP-Enabled Remote Power Reboot Switch to
    reset a device under test (DUT).

    In addition to reset(), post_fail() is provided, meant to be given as a
    callback to a Session object.

    It uses undocumented yet simple CGI scripts.
    """
    DEFAULT_RESET_DELAY = 3.05
    RESET_URL_PATH = '/reset.cgi'
    EXPECTED_RESPONSE_CONTENTS = '0,0'
    NO_RESPONSE_MSG = "No response from EzOutlet. timeout value: {0}"
    UNEXPECTED_RESPONSE_MSG = ("Unexpected response from EzOutlet. Expected: " +
                               repr(EXPECTED_RESPONSE_CONTENTS) +
                               " Actual: {0}")
    LOG_REQUEST_MSG = 'HTTP GET {0}'

    def __init__(self, hostname, dut_reset_time=0, timeout=30, reset_delay=DEFAULT_RESET_DELAY):
        """
        Args:
            hostname: Hostname or IP address of device.
            dut_reset_time: Time in seconds to allow the device under test
                to reboot.
            timeout: Time in seconds to wait for the EzOutlet to respond.
            reset_delay: Time the EzOutlet waits before switching back on.
        """
        self._hostname = hostname
        self._dut_reset_time = dut_reset_time
        self._timeout = timeout
        self._reset_delay = reset_delay

    @property
    def url(self):
        return _get_url(self._hostname, self.RESET_URL_PATH)

    def post_fail(self, logger, *args, **kwargs):
        """Tries to reset device over HTTP and wait before returning.

        After sending HTTP request and receiving response, wait
        self._reset_delay + self._dut_reset_time seconds.

        If the outlet does not respond (after self._timeout seconds), this
        method will raise an exception.

        This method will log actions associated with HTTP communication. It
        assumes that a test step is already opened.

        Args:
            logger (ifuzz_logger.IFuzzLogger):
                For logging communications with outlet device.
            *args: Kept for forward-compatibility.
            **kwargs: Kept for forward-compatibility.

        Raises:
            sex.SulleyRuntimeError: If the reset fails due to:
                - no response in self._timeout seconds or
                - unexpected response contents (see
                  EzOutletReset.EXPECTED_RESPONSE_CONTENTS)
        """
        _ = args  # only for forward-compatibility
        _ = kwargs  # only for forward-compatibility

        logger.log_info(self.LOG_REQUEST_MSG.format(self.url))

        try:
            response = self.reset()
            logger.log_recv(response)
        except sex.SullyRuntimeError as e:
            logger.log_info(e.message)
            raise

    def reset(self):
        """Send reset request to ezOutlet device and wait for reset.

        Returns: HTTP response contents.

        Raises sex.SullyRuntimeError if device does not respond as expected.
        """
        response = self._http_get(self.url)

        self._check_response(response)

        self._wait_for_reset()

        return response

    def _http_get(self, url):
        target_connection = self._connect_target(url)
        return target_connection.read()

    def _connect_target(self, url):
        try:
            return urllib2.urlopen(url, timeout=self._timeout)
        except urllib2.URLError:
            raise sex.SullyRuntimeError(self.NO_RESPONSE_MSG.format(self._timeout)), \
                None, \
                sys.exc_info()[2]

    def _check_response(self, response):
        if response != self.EXPECTED_RESPONSE_CONTENTS:
            raise sex.SullyRuntimeError(self.UNEXPECTED_RESPONSE_MSG.format(response))

    def _wait_for_reset(self):
        time.sleep(self._reset_delay + self._dut_reset_time)
