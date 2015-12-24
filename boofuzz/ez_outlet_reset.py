import sys
import time
import urllib2
import urlparse
import ifuzz_logger

import sex


def _build_url(hostname, path):
    return urlparse.urlunparse(('http', hostname, path, '', '', ''))


class EzOutletReset:
    """Uses ezOutlet EZ-11b to reset a device.

    Uses the ezOutlet EZ-11b Internet IP-Enabled Remote Power Reboot Switch to
    reset a device under test (DUT).

    It provides a post_fail method, meant to be given as a callback to a
    Session object.

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
        logger = logger

        url = _build_url(self._hostname, self.RESET_URL_PATH)

        logger.log_info(self.LOG_REQUEST_MSG.format(url))

        try:
            opened_url = urllib2.urlopen(url, timeout=self._timeout)
        except urllib2.URLError:
            if logger is not None:
                logger.log_info(self.NO_RESPONSE_MSG.format(self._timeout))
            raise sex.SullyRuntimeError(self.NO_RESPONSE_MSG.format(self._timeout)), \
                None, \
                sys.exc_info()[2]

        received = opened_url.read()

        logger.log_recv(received)

        if received != self.EXPECTED_RESPONSE_CONTENTS:
            raise sex.SullyRuntimeError(self.UNEXPECTED_RESPONSE_MSG.format(received))

        time.sleep(self._reset_delay + self._dut_reset_time)
