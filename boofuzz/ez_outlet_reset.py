from __future__ import print_function

import argparse
import os
import sys
import time
import traceback
import urllib2
import urlparse

import ifuzz_logger
import sex

_DEFAULT_RESET_DELAY = 3.05

HELP_TEXT = (
    """Send reset command to ezOutlet EZ-11b device; wait for on/off cycle.

    Use --reset-time to wait additional time, e.g. for device reboot."""
)
PROGRAM_NAME = os.path.basename(__file__)
RESET_TIME_ARG_SHORT = '-t'
RESET_TIME_ARG_LONG = '--reset-time'

HELP_TEXT_TARGET_ARG = 'IP address/hostname of ezOutlet device.'
HELP_TEXT_RESET_TIME_ARG = 'Extra time in seconds to wait, e.g. for device reboot.' \
                           ' Note that the script already waits {0} seconds for the' \
                           ' ezOutlet to turn off and on.'.format(_DEFAULT_RESET_DELAY)

ERROR_STRING = "{0}: error: {1}"
UNHANDLED_ERROR_MESSAGE = "Unhandled exception! Please file bug report.\n\n{0}"
RESET_TIME_NEGATIVE_ERROR_MESSAGE = "argument{0}/{1}: value must be non-negative.".format(RESET_TIME_ARG_LONG,
                                                                                          RESET_TIME_ARG_SHORT)

EXIT_CODE_ERR = 1
EXIT_CODE_PARSER_ERR = 2


class EzOutletResetError(Exception):
    pass


class EzOutletResetUsageError(EzOutletResetError):
    pass


def _get_url(hostname, path):
    return urlparse.urlunparse(('http', hostname, path, '', '', ''))


class EzOutletReset:
    """Uses ezOutlet EZ-11b to reset a device.

    Uses the ezOutlet EZ-11b Internet IP-Enabled Remote Power Reboot Switch to
    reset a device under test (DUT).

    In addition to reset(), post_fail() is provided, meant to be given as a
    callback to a Session object.

    It uses undocumented but simple CGI scripts.
    """
    DEFAULT_RESET_DELAY = _DEFAULT_RESET_DELAY
    DEFAULT_TIMEOUT = 10
    DEFAULT_WAIT_TIME = 0
    RESET_URL_PATH = '/reset.cgi'
    EXPECTED_RESPONSE_CONTENTS = '0,0'
    NO_RESPONSE_MSG = "No response from EzOutlet after {0} seconds."
    UNEXPECTED_RESPONSE_MSG = ("Unexpected response from EzOutlet. Expected: " +
                               repr(EXPECTED_RESPONSE_CONTENTS) +
                               " Actual: {0}")
    LOG_REQUEST_MSG = 'HTTP GET {0}'

    def __init__(self, hostname, wait_time=0, timeout=DEFAULT_TIMEOUT, reset_delay=DEFAULT_RESET_DELAY):
        """
        Args:
            hostname: Hostname or IP address of device.
            wait_time: Time in seconds to allow the device being reset
                to reboot. See also reset_delay.
            timeout: Time in seconds to wait for the EzOutlet to respond.
            reset_delay: Time the EzOutlet waits before switching back on.
        """
        self._hostname = hostname
        self._dut_reset_time = wait_time
        self._timeout = timeout
        self._reset_delay = reset_delay

    @property
    def url(self):
        return _get_url(self._hostname, self.RESET_URL_PATH)

    def post_fail(self, logger, *args, **kwargs):
        """Call reset() and log actions.

        See reset() docstring for details.

        This method will log actions associated with HTTP communication. It
        assumes that a test step is already opened.

        Args:
            logger (ifuzz_logger.IFuzzLogger):
                For logging communications with outlet device.
            *args: Kept for forward-compatibility.
            **kwargs: Kept for forward-compatibility.

        Raises:
            sex.SullyRuntimeError: If the reset fails due to:
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
        except EzOutletResetError as e:
            logger.log_info(e.message)
            raise sex.SullyRuntimeError(e.message), \
                None, \
                sys.exc_info()[2]

    def reset(self):
        """Send reset request to ezOutlet, check response, wait for reset.

        After sending HTTP request and receiving response, wait
        self._reset_delay + self._dut_reset_time seconds.

        If the outlet does not respond (after self._timeout seconds), or gives
        an unexpected response, this method will raise an exception.

        Returns: HTTP response contents.

        Raises:
            EzOutletResetError: If the reset fails due to:
                - no response in self._timeout seconds or
                - unexpected response contents (see
                  EzOutletReset.EXPECTED_RESPONSE_CONTENTS)
        """
        response = self._http_get(self.url)

        self._check_response_raise_if_unexpected(response)

        self._wait_for_reset()

        return response

    def _http_get(self, url):
        """HTTP GET and return response.

        Args:
            url: Target to GET.

        Returns: Response contents.

        Raises:
            EzOutletResetError: If the reset fails due to:
                - no response in self._timeout seconds
        """
        try:
            return urllib2.urlopen(url, timeout=self._timeout).read()
        except urllib2.URLError:
            raise EzOutletResetError(self.NO_RESPONSE_MSG.format(self._timeout)), \
                None, \
                sys.exc_info()[2]

    def _check_response_raise_if_unexpected(self, response):
        """Raise if response is unexpected.

        Args:
            response: Response.

        Returns: None

        Raises:
            EzOutletResetError: If the reset fails due to:
                - unexpected response contents (see
                  EzOutletReset.EXPECTED_RESPONSE_CONTENTS)
        """
        if response != self.EXPECTED_RESPONSE_CONTENTS:
            raise EzOutletResetError(self.UNEXPECTED_RESPONSE_MSG.format(response))

    def _wait_for_reset(self):
        """Sleep for self._reset_delay + self._dut_reset_time.

        Returns: None
        """
        time.sleep(self._reset_delay + self._dut_reset_time)


class _Parser(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser(description=HELP_TEXT)
        self.parser.add_argument('target', help=HELP_TEXT_TARGET_ARG)
        self.parser.add_argument(RESET_TIME_ARG_LONG, RESET_TIME_ARG_SHORT,
                                 type=float,
                                 default=0,
                                 help=HELP_TEXT_RESET_TIME_ARG)

    def get_usage(self):
        return self.parser.format_usage()

    def parse_args(self, argv):
        parsed_args = self.parser.parse_args(argv[1:])

        self._check_args(parsed_args)

        return parsed_args

    @staticmethod
    def _check_args(parsed_args):
        if parsed_args.reset_time < 0:
            raise EzOutletResetUsageError(RESET_TIME_NEGATIVE_ERROR_MESSAGE)

_parser = _Parser()


def _print_usage():
    print(_parser.get_usage(), file=sys.stderr)


def _print_error(msg):
    print(ERROR_STRING.format(PROGRAM_NAME, msg), file=sys.stderr)


def _usage_error(exception):
    _print_usage()
    _print_error(msg=exception.message)
    sys.exit(EXIT_CODE_PARSER_ERR)


def _handle_error(exception):
    _print_error(msg=exception.message)
    sys.exit(EXIT_CODE_ERR)


def _handle_unexpected_error(exception):
    _ = exception  # exception gets printed by traceback.format_exc()
    _print_error(msg=UNHANDLED_ERROR_MESSAGE.format(traceback.format_exc()))
    sys.exit(EXIT_CODE_ERR)


def _parse_args_and_reset(argv):
    parsed_args = _parser.parse_args(argv)
    ez_outlet = EzOutletReset(hostname=parsed_args.target,
                              wait_time=parsed_args.reset_time)
    ez_outlet.reset()


def main(argv):
    try:
        _parse_args_and_reset(argv)
    except EzOutletResetUsageError as e:
        _usage_error(e)
    except EzOutletResetError as e:
        _handle_error(e)
    except Exception as e:
        _handle_unexpected_error(e)


if __name__ == "__main__":
    main(sys.argv)
