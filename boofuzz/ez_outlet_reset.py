import sys
import time
import urllib2
import urlparse

import sex


def _build_url(hostname, path):
    return urlparse.urlunparse(('http', hostname, path, '', '', ''))


class EzOutletReset:
    """
    This module uses the ezOutlet EZ-11b Internet IP-Enabled Remote Power
    Reboot Switch to reset a device under test (DUT).

    It provides a post_fail method, meant to be given as a callback to a
    Session object.

    It uses undocumented yet simple CGI scripts.
    """
    DEFAULT_RESET_DELAY = 3.05
    RESET_URL_PATH = '/reset.cgi'
    NO_RESPONSE_MSG = "No response from EzOutlet. timeout value: {0}"
    LOG_REQUEST_MSG = 'HTTP GET {0}'

    def __init__(self, hostname, dut_reset_time=0, timeout=30, reset_delay=DEFAULT_RESET_DELAY):
        """
        @param hostname: Hostname or IP address of device.
        @param dut_reset_time: Time in seconds to allow the device under test
                               to reboot.
        @param timeout: Time in seconds to wait for the EzOutlet to respond.
        @param reset_delay: Time the EzOutlet waits before switching back on.
        """
        self._hostname = hostname
        self._dut_reset_time = dut_reset_time
        self._timeout = timeout
        self._reset_delay = reset_delay

    def post_fail(self, *args, **kwargs):
        """
        Tries to reset device over HTTP and wait based on self.reset_delay
        + self._dut_reset_time seconds.

        If the outlet does not respond, this method will raise an exception.

        @:raises: sex.SullyRuntimeError if the reset fails.
        """
        _ = args  # only for forward-compatibility
        try:
            logger = kwargs['logger']
        except KeyError:
            logger = None

        url = _build_url(self._hostname, self.RESET_URL_PATH)

        if logger is not None:
            logger.log_info(self.LOG_REQUEST_MSG.format(url))

        try:
            opened_rul = urllib2.urlopen(url, timeout=self._timeout)
        except urllib2.URLError:
            if logger is not None:
                logger.log_info(self.NO_RESPONSE_MSG.format(self._timeout))
            raise sex.SullyRuntimeError(self.NO_RESPONSE_MSG.format(self._timeout)), \
                None, \
                sys.exc_info()[2]

        if logger is not None:
            logger.log_recv(opened_rul.read())

        time.sleep(self._reset_delay + self._dut_reset_time)
