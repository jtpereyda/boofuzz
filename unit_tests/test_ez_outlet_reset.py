import StringIO
import re
import unittest
import urllib2

import pytest

try:
    import unittest.mock as mock
except ImportError:
    # mock is required as an extras_require:
    # noinspection PyPackageRequirements
    import mock

import boofuzz
from boofuzz import ez_outlet_reset

EXIT_CODE_ERR = 1
EXIT_CODE_PARSER_ERR = 2


class TestEzOutletReset(unittest.TestCase):
    """
    EzOutletReset.post_fail is basically all side-effects, so its test is
    rather heavy in mocks.
    """

    arbitrary_msg_1 = 'arbitrary message'
    arbitrary_msg_2 = '"Always check a module in cleaner than when you checked it out." --Uncle Bob'

    sample_url = 'DEAD STRINGS TELL NO TALES'
    expected_response_contents = boofuzz.EzOutletReset.EXPECTED_RESPONSE_CONTENTS
    unexpected_response_contents = '1,0'

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured such that
               urlopen returns a mock whose read() method returns expected_response_contents.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling post_fail() with a mock_logger.
        Then: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: mock_logger.log_info(EzOutletReset.LOG_REQUEST_MSG.format(sample_url)) is called
              where sample_rul is ez_outlet_reset._get_url's result.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: mock_logger.log_recv() is called with expected_response_contents.
         and: time.sleep(wait_time + reset_delay) is called.
        """
        # Given
        mock_urllib2.configure_mock(
                **{'urlopen.return_value': mock.MagicMock(
                        **{'read.return_value': self.expected_response_contents})})
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        e = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                  wait_time=wait_time,
                                                  timeout=timeout,
                                                  reset_delay=reset_delay)

        # When
        mock_logger = mock.MagicMock(spec=boofuzz.IFuzzLogger)
        # PyCharm can't match MagicMock types.
        # noinspection PyTypeChecker
        e.post_fail(logger=mock_logger)

        # Then
        mock_logger.log_info.assert_called_once_with(
                boofuzz.ez_outlet_reset.EzOutletReset.LOG_REQUEST_MSG.format(self.sample_url))
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_logger.log_recv.assert_called_once_with(self.expected_response_contents)
        mock_time.sleep.assert_called_once_with(wait_time + reset_delay)

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail_no_response(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured to raise urllib2.URLError on urlopen.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling post_fail() with a mock_logger.
        Then: post_fail() raises boofuzz.sex.SullyRuntimeError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: mock_logger.log_info() is called in this order with these parameters:
               1. EzOutletReset.LOG_REQUEST_MSG.format(sample_url)
                  where sample_rul is ez_outlet_reset._get_url's result.
               2. EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: mock_logger.log_recv() is _not_ called
         and: time.sleep(wait_time + reset_delay) is _not_ called.
        """
        # Given
        mock_urllib2.configure_mock(**{'urlopen.side_effect': urllib2.URLError("Dummy reason")})
        mock_urllib2.URLError = urllib2.URLError  # Restore mocked-away URLError
        # and
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        ez = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                   wait_time=wait_time,
                                                   timeout=timeout,
                                                   reset_delay=reset_delay)

        # When
        mock_logger = mock.MagicMock(spec=boofuzz.IFuzzLogger)
        with self.assertRaises(boofuzz.sex.SullyRuntimeError) as e:
            # PyCharm can't match MagicMock types.
            # noinspection PyTypeChecker
            ez.post_fail(logger=mock_logger)

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout))
        mock_logger.log_info.assert_has_calls([
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.LOG_REQUEST_MSG.format(self.sample_url)),
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout)),
        ]
        )
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_logger.log_recv.assert_not_called()
        mock_time.sleep.assert_not_called()

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_post_fail_unexpected_response(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured such that
               urlopen returns a mock whose read() method returns unexpected_response_contents.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling post_fail() with a mock_logger.
        Then: post_fail() raises boofuzz.sex.SullyRuntimeError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(unexpected_response_contents).
         and: mock_logger.log_info() is called in this order with these parameters:
               1. EzOutletReset.LOG_REQUEST_MSG.format(sample_url)
                  where sample_rul is ez_outlet_reset._get_url's result.
               2. EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(unexpected_response_contents).
         and: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: time.sleep(wait_time + reset_delay) is _not_ called.
        """
        # Given
        mock_urllib2.configure_mock(
                **{'urlopen.return_value': mock.MagicMock(
                        **{'read.return_value': self.unexpected_response_contents})})
        # and
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        ez = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                   wait_time=wait_time,
                                                   timeout=timeout,
                                                   reset_delay=reset_delay)

        # When
        mock_logger = mock.MagicMock(spec=boofuzz.IFuzzLogger)
        with self.assertRaises(boofuzz.sex.SullyRuntimeError) as e:
            # PyCharm can't match MagicMock types.
            # noinspection PyTypeChecker
            ez.post_fail(logger=mock_logger)

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(
                                 self.unexpected_response_contents))
        mock_logger.log_info.assert_has_calls([
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.LOG_REQUEST_MSG.format(self.sample_url)),
            mock.call(boofuzz.ez_outlet_reset.EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(
                    self.unexpected_response_contents)),
        ]
        )
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_time.sleep.assert_not_called()

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_reset(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured such that
               urlopen returns a mock whose read() method returns expected_response_contents.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling reset().
        Then: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: expected_response_contents is returned.
         and: time.sleep(wait_time + reset_delay) is called.
        """
        # Given
        mock_urllib2.configure_mock(
                **{'urlopen.return_value': mock.MagicMock(
                        **{'read.return_value': self.expected_response_contents})})
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        uut = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                    wait_time=wait_time,
                                                    timeout=timeout,
                                                    reset_delay=reset_delay)

        # When
        result = uut.reset()

        # Then
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        self.assertEqual(self.expected_response_contents, result)
        mock_time.sleep.assert_called_once_with(wait_time + reset_delay)

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_reset_no_response(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured to raise urllib2.URLError on urlopen.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling reset().
        Then: reset() raises boofuzz.ez_outlet_reset.EzOutletResetError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout).
         and: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: time.sleep(wait_time + reset_delay) is _not_ called.
        """
        # Given
        mock_urllib2.configure_mock(**{'urlopen.side_effect': urllib2.URLError("Dummy reason")})
        mock_urllib2.URLError = urllib2.URLError  # Restore mocked-away URLError
        # and
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        ez = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                   wait_time=wait_time,
                                                   timeout=timeout,
                                                   reset_delay=reset_delay)

        # When
        with self.assertRaises(boofuzz.ez_outlet_reset.EzOutletResetError) as e:
            ez.reset()

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.NO_RESPONSE_MSG.format(timeout))
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_time.sleep.assert_not_called()

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch.object(boofuzz.ez_outlet_reset, '_get_url', return_value=sample_url)
    @mock.patch('boofuzz.ez_outlet_reset.urllib2')
    @mock.patch('boofuzz.ez_outlet_reset.time')
    def test_reset_unexpected_response(self, mock_time, mock_urllib2, mock_get_url):
        """
        Given: Mock urllib2 configured such that
               urlopen returns a mock whose read() method returns unexpected_response_contents.
          and: EzOutletReset initialized with an IP address, wait_time, timeout, and reset_delay.
        When: Calling reset().
        Then: reset() raises boofuzz.ez_outlet_reset.EzOutletResetError, e.
         and: e.message == ez_outlet_reset.EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(unexpected_response_contents).
         and: ez_outlet_reset._get_url is called using the IP address with ez_outlet_reset.RESET_URL_PATH.
         and: urllib2.urlopen(ez_outlet_reset._get_url's result, timeout) is called.
         and: time.sleep(wait_time + reset_delay) is _not_ called.
        """
        # Given
        mock_urllib2.configure_mock(
                **{'urlopen.return_value': mock.MagicMock(
                        **{'read.return_value': self.unexpected_response_contents})})
        # and
        hostname = '12.34.56.78'
        wait_time = 12.34
        reset_delay = 3.21
        timeout = 11.12
        ez = boofuzz.ez_outlet_reset.EzOutletReset(hostname=hostname,
                                                   wait_time=wait_time,
                                                   timeout=timeout,
                                                   reset_delay=reset_delay)

        # When
        with self.assertRaises(boofuzz.ez_outlet_reset.EzOutletResetError) as e:
            ez.reset()

        # Then
        self.assertEqual(e.exception.message,
                         boofuzz.ez_outlet_reset.EzOutletReset.UNEXPECTED_RESPONSE_MSG.format(
                                 self.unexpected_response_contents))
        mock_get_url.assert_called_with(hostname, boofuzz.ez_outlet_reset.EzOutletReset.RESET_URL_PATH)
        mock_urllib2.urlopen.assert_called_once_with(self.sample_url, timeout=timeout)
        mock_time.sleep.assert_not_called()

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.EzOutletReset')
    def test_main_basic(self, mock_ez_outlet_reset):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with a single argument.
        Then: EzOutletReset constructor is called with hostname == given value
              and wait_time == ez_outlet_reset.DEFAULT_WAIT_TIME.
         and: STDOUT is silent.
        """
        hostname = '255.254.253.252'
        args = ['ez_outlet_reset.py', hostname]

        ez_outlet_reset.main(args)

        mock_ez_outlet_reset.assert_called_once_with(hostname=hostname,
                                                     wait_time=boofuzz.EzOutletReset.DEFAULT_WAIT_TIME)
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.EzOutletReset')
    def test_main_reset_time_long(self, mock_ez_outlet_reset):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with hostname and --reset-time arguments.
        Then: EzOutletReset constructor is called with hostname == given value
              and wait_time == given value.
         and: STDOUT is silent.
        """
        hostname = '255.254.253.252'
        wait_time = 77
        args = ['ez_outlet_reset.py', hostname, ez_outlet_reset.RESET_TIME_ARG_LONG, str(wait_time)]

        ez_outlet_reset.main(args)

        mock_ez_outlet_reset.assert_called_once_with(hostname=hostname,
                                                     wait_time=wait_time)
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.EzOutletReset')
    def test_main_reset_time_short(self, mock_ez_outlet_reset):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with hostname and -t arguments.
        Then: EzOutletReset constructor is called with hostname == given value
              and wait_time == given value.
         and: STDOUT is silent.
        """
        hostname = '255.254.253.252'
        wait_time = 1
        args = ['ez_outlet_reset.py', hostname, ez_outlet_reset.RESET_TIME_ARG_SHORT, str(wait_time)]

        ez_outlet_reset.main(args)

        mock_ez_outlet_reset.assert_called_once_with(hostname=hostname,
                                                     wait_time=wait_time)
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    def test_main_missing_target(self):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with no arguments.
        Then: SystemExit is raised with code EXIT_CODE_PARSER_ERR
         and: STDERR includes ".*: error: too few arguments"
         and: STDOUT is silent.
        """
        args = ['ez_outlet_reset.py']

        with pytest.raises(SystemExit) as exception_info:
            ez_outlet_reset.main(args)

        assert exception_info.value.message == EXIT_CODE_PARSER_ERR

        assert re.search(".*: error: too few arguments", boofuzz.ez_outlet_reset.sys.stderr.getvalue()) is not None

        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    def test_main_unknown_arg(self, ):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with required arguments and an extra unknown argument.
        Then: SystemExit is raised with code EXIT_CODE_PARSER_ERR
         and: STDERR <= ".*: error: unrecognized arguments: {0}".format(bad_arg)
         and: STDOUT is silent.
        """
        bad_arg = '--blab'
        args = ['ez_outlet_reset.py', '1.2.3.4', bad_arg]

        with pytest.raises(SystemExit) as exception_info:
            ez_outlet_reset.main(args)

        assert exception_info.value.message == EXIT_CODE_PARSER_ERR

        assert re.search(".*: error: unrecognized arguments: {0}".format(bad_arg),
                         boofuzz.ez_outlet_reset.sys.stderr.getvalue()) is not None
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    def test_main_reset_time_negative(self):
        """
        Given: Mock EzOutletReset.
        When: Calling main() with hostname and negative reset time argument.
        Then: SystemExit is raised with code EXIT_CODE_PARSER_ERR
         and: STDERR <= ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME,
                                                             ez_outlet_reset.RESET_TIME_NEGATIVE_ERROR_MESSAGE)
         and: STDOUT is silent.
        """
        args = ['ez_outlet_reset.py', '1.2.3.4', ez_outlet_reset.RESET_TIME_ARG_LONG, str(-1)]

        with pytest.raises(SystemExit) as exception_info:
            ez_outlet_reset.main(args)

        assert exception_info.value.message == EXIT_CODE_PARSER_ERR

        assert re.search(ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME,
                                                             ez_outlet_reset.RESET_TIME_NEGATIVE_ERROR_MESSAGE),
                         boofuzz.ez_outlet_reset.sys.stderr.getvalue()) is not None
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    @mock.patch.object(boofuzz.ez_outlet_reset._Parser, 'parse_args',
                       side_effect=ez_outlet_reset.EzOutletResetUsageError(arbitrary_msg_1))
    def test_error_handling_ez_outlet_reset_usage_error(self, mock_parser):
        """
        Given: Mock ez_outlet_reset._Parser() configured to raise on
               parse_args().
          and: Mock STDERR, STDOUT.
         When: Calling main().
         Then: SystemExit is raised with code EXIT_CODE_PARSER_ERR
          and: STDERR <= ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME, self.arbitrary_msg_1)
          and: STDOUT is silent.
          and: Mock ez_outlet_reset._Parser.parse_args() was called.
        """
        args = ['ez_outlet_reset.py', '1.2.3.4']

        # When
        with pytest.raises(SystemExit) as exception_info:
            boofuzz.ez_outlet_reset.main(args)

        # Then
        assert exception_info.value.message == EXIT_CODE_PARSER_ERR

        assert re.search(ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME, self.arbitrary_msg_1),
                         boofuzz.ez_outlet_reset.sys.stderr.getvalue()) is not None
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

        mock_parser.assert_called_with(args)

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    @mock.patch.object(boofuzz.ez_outlet_reset.EzOutletReset, 'reset',
                       side_effect=ez_outlet_reset.EzOutletResetError(arbitrary_msg_2))
    def test_error_handling_ez_outlet_reset_error(self, mock_ez_outlet_reset):
        """
        Given: Mock ez_outlet_reset.EzOutletReset() configured to raise on
               EzOutletResetError on reset().
          and: Mock STDERR, STDOUT.
         When: Calling main().
         Then: SystemExit is raised with code EXIT_CODE_ERR
          and: STDERR <= ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME, self.arbitrary_msg_2)
          and: STDOUT is silent.
          and: Mock ez_outlet_reset.EzOutletReset.reset() was called.
        """
        args = ['ez_outlet_reset.py', '1.2.3.4']

        # When
        with pytest.raises(SystemExit) as exception_info:
            boofuzz.ez_outlet_reset.main(args)

        # Then
        assert exception_info.value.message == EXIT_CODE_ERR

        assert re.search(ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME, self.arbitrary_msg_2),
                         boofuzz.ez_outlet_reset.sys.stderr.getvalue()) is not None
        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

        mock_ez_outlet_reset.assert_called_with()

    # Suppress since PyCharm doesn't recognize @mock.patch.object
    # noinspection PyUnresolvedReferences
    @mock.patch('boofuzz.ez_outlet_reset.sys.stdout', new=StringIO.StringIO())
    @mock.patch('boofuzz.ez_outlet_reset.sys.stderr', new=StringIO.StringIO())
    @mock.patch.object(boofuzz.ez_outlet_reset.EzOutletReset, 'reset',
                       side_effect=Exception(arbitrary_msg_2))
    def test_error_handling_unhandled_error(self, mock_ez_outlet_reset):
        """
        Given: Mock ez_outlet_reset.EzOutletReset.reset() configured to raise an
               Exception on reset().
          and: Mock STDERR, STDOUT.
         When: Calling main().
         Then: SystemExit is raised with code EXIT_CODE_ERR
          and: STDERR <= ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME,
                                                             ez_outlet_reset.UNHANDLED_ERROR_MESSAGE.format(
                                                                 "Traceback.*{0}.*".format(self.arbitrary_msg_2)))
          and: STDOUT is silent.
          and: Mock ez_outlet_reset.EzOutletReset.reset() was called.
        """
        args = ['ez_outlet_reset.py', '1.2.3.4']

        # When
        with pytest.raises(SystemExit) as exception_info:
            boofuzz.ez_outlet_reset.main(args)

        # Then
        assert exception_info.value.message == EXIT_CODE_ERR

        assert re.search(ez_outlet_reset.ERROR_STRING.format(ez_outlet_reset.PROGRAM_NAME,
                                                             ez_outlet_reset.UNHANDLED_ERROR_MESSAGE.format(
                                                                     "Traceback.*{0}.*".format(self.arbitrary_msg_2))),
                         boofuzz.ez_outlet_reset.sys.stderr.getvalue(),
                         flags=re.DOTALL) is not None

        assert boofuzz.ez_outlet_reset.sys.stdout.getvalue() == ''

        mock_ez_outlet_reset.assert_called_with()


@pytest.mark.parametrize("hostname,expected_url", [('1.2.3.4', 'http://1.2.3.4/reset.cgi')])
def test_url(hostname, expected_url):
    """
    Given: A hostname.
    When: Creating an EzOutletReset using hostname.
    Then: Property `url` returns the expected URL.

    Args:
        hostname: test parameter
        expected_url: test parameter
    """
    uut = boofuzz.EzOutletReset(hostname=hostname)

    assert expected_url == uut.url
