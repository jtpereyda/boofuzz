import sys
import time
import urllib2

import sex


class EzOutletReset:
    """
    This module uses the ezOutlet EZ-11b Internet IP-Enabled Remote Power
    Reboot Switch to reset a device under test (DUT).

    It provides a post_fail method, meant to be given as a callback to a
    Session object.

    It uses undocumented yet simple CGI scripts.
    """
    DEFAULT_RESET_DELAY = 3.05

    def __init__(self, dut_reset_time=0, timeout=30, reset_delay=DEFAULT_RESET_DELAY):
        """
        @param dut_reset_time: Time in seconds to allow the device under test
                               to reboot.
        @param timeout: Time in seconds to wait for the EzOutlet to respond.
        @param reset_delay: Time the EzOutlet waits before switching back on.
        """
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
        _ = kwargs  # only for forward-compatibility
        # TODO log sent/received for debugging.
        try:
            urllib2.urlopen("http://172.16.3.174/reset.cgi", timeout=self._timeout)
        except urllib2.URLError:
            raise sex.SullyRuntimeError("EzOutlet did not respond in time. timeout value: {0}".format(self._timeout)), \
                   None, \
                   sys.exc_info()[2]
        time.sleep(self._reset_delay + self._dut_reset_time)
