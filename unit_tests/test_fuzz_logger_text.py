from __future__ import absolute_import
from __future__ import unicode_literals
from builtins import bytes, chr
import unittest
import re
import StringIO

import boofuzz.helpers
from boofuzz import fuzz_logger_text

LOGGER_PREAMBLE = ".*"
TEST_CASE_FORMAT = fuzz_logger_text.FuzzLoggerText.TEST_CASE_FORMAT + '\n'
TEST_STEP_FORMAT = fuzz_logger_text.FuzzLoggerText.TEST_STEP_FORMAT + '\n'
LOG_CHECK_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_CHECK_FORMAT + '\n'
LOG_INFO_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_INFO_FORMAT + '\n'
LOG_PASS_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_PASS_FORMAT + '\n'
LOG_FAIL_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_FAIL_FORMAT + '\n'
LOG_RECV_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_RECV_FORMAT + '\n'
LOG_SEND_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_SEND_FORMAT + '\n'
LOG_ERROR_FORMAT = fuzz_logger_text.FuzzLoggerText.LOG_ERROR_FORMAT + '\n'
DEFAULT_TEST_CASE_ID = fuzz_logger_text.FuzzLoggerText.DEFAULT_TEST_CASE_ID


class TestFuzzLoggerTextFreeFunctions(unittest.TestCase):
    def test_get_time_stamp(self):
        """
        Given: No context.
        When: Calling get_time_stamp().
        Then: get_time_stamp() returns time stamp in proper format.
        """
        # When
        s = boofuzz.helpers.get_time_stamp()

        # Then
        self.assertRegexpMatches(s, '\[\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d\d\d\]')

    def test_hex_to_hexstr(self):
        """
        Given: A set of bytes representing a string with several lines.
        When: Calling hex_to_hexstr
        Then: Hex of several-line string is output first, then repr format.
        """
        given = "abc\n123\r\nA\n"
        expected = "61 62 63 0a 31 32 33 0d 0a 41 0a b'abc\\n123\\r\\nA\\n'"
        self.assertEqual(expected, boofuzz.helpers.hex_to_hexstr(bytes(given, 'latin-1')))

    def test_hex_to_hexstr_all_bytes(self):
        """
        Given: List of each byte from 0 to 255.
        When: Calling hex_to_hexstr on each.
        Then: For each byte, its hex value is output, followed by its repr
              value.
        """
        # Use a static map so that future changes are detected by the UT,
        # to avoid Python 3 vs Python 2 errors, etc.
        expected_results = {
            0: "b'\\x00'", 1: "b'\\x01'", 2: "b'\\x02'", 3: "b'\\x03'",
            4: "b'\\x04'", 5: "b'\\x05'", 6: "b'\\x06'", 7: "b'\\x07'",
            8: "b'\\x08'", 9: "b'\\t'", 10: "b'\\n'", 11: "b'\\x0b'",
            12: "b'\\x0c'", 13: "b'\\r'", 14: "b'\\x0e'", 15: "b'\\x0f'",
            16: "b'\\x10'", 17: "b'\\x11'", 18: "b'\\x12'", 19: "b'\\x13'",
            20: "b'\\x14'", 21: "b'\\x15'", 22: "b'\\x16'", 23: "b'\\x17'",
            24: "b'\\x18'", 25: "b'\\x19'", 26: "b'\\x1a'", 27: "b'\\x1b'",
            28: "b'\\x1c'", 29: "b'\\x1d'", 30: "b'\\x1e'", 31: "b'\\x1f'",
            32: "b' '", 33: "b'!'", 34: 'b\'"\'', 35: "b'#'",
            36: "b'$'", 37: "b'%'", 38: "b'&'", 39: 'b"\'"',
            40: "b'('", 41: "b')'", 42: "b'*'", 43: "b'+'",
            44: "b','", 45: "b'-'", 46: "b'.'", 47: "b'/'",
            48: "b'0'", 49: "b'1'", 50: "b'2'", 51: "b'3'",
            52: "b'4'", 53: "b'5'", 54: "b'6'", 55: "b'7'",
            56: "b'8'", 57: "b'9'", 58: "b':'", 59: "b';'",
            60: "b'<'", 61: "b'='", 62: "b'>'", 63: "b'?'",
            64: "b'@'", 65: "b'A'", 66: "b'B'", 67: "b'C'",
            68: "b'D'", 69: "b'E'", 70: "b'F'", 71: "b'G'",
            72: "b'H'", 73: "b'I'", 74: "b'J'", 75: "b'K'",
            76: "b'L'", 77: "b'M'", 78: "b'N'", 79: "b'O'",
            80: "b'P'", 81: "b'Q'", 82: "b'R'", 83: "b'S'",
            84: "b'T'", 85: "b'U'", 86: "b'V'", 87: "b'W'",
            88: "b'X'", 89: "b'Y'", 90: "b'Z'", 91: "b'['",
            92: "b'\\\\'", 93: "b']'", 94: "b'^'", 95: "b'_'",
            96: "b'`'", 97: "b'a'", 98: "b'b'", 99: "b'c'",
            100: "b'd'", 101: "b'e'", 102: "b'f'", 103: "b'g'",
            104: "b'h'", 105: "b'i'", 106: "b'j'", 107: "b'k'",
            108: "b'l'", 109: "b'm'", 110: "b'n'", 111: "b'o'",
            112: "b'p'", 113: "b'q'", 114: "b'r'", 115: "b's'",
            116: "b't'", 117: "b'u'", 118: "b'v'", 119: "b'w'",
            120: "b'x'", 121: "b'y'", 122: "b'z'", 123: "b'{'",
            124: "b'|'", 125: "b'}'", 126: "b'~'", 127: "b'\\x7f'",
            128: "b'\\x80'", 129: "b'\\x81'", 130: "b'\\x82'", 131: "b'\\x83'",
            132: "b'\\x84'", 133: "b'\\x85'", 134: "b'\\x86'", 135: "b'\\x87'",
            136: "b'\\x88'", 137: "b'\\x89'", 138: "b'\\x8a'", 139: "b'\\x8b'",
            140: "b'\\x8c'", 141: "b'\\x8d'", 142: "b'\\x8e'", 143: "b'\\x8f'",
            144: "b'\\x90'", 145: "b'\\x91'", 146: "b'\\x92'", 147: "b'\\x93'",
            148: "b'\\x94'", 149: "b'\\x95'", 150: "b'\\x96'", 151: "b'\\x97'",
            152: "b'\\x98'", 153: "b'\\x99'", 154: "b'\\x9a'", 155: "b'\\x9b'",
            156: "b'\\x9c'", 157: "b'\\x9d'", 158: "b'\\x9e'", 159: "b'\\x9f'",
            160: "b'\\xa0'", 161: "b'\\xa1'", 162: "b'\\xa2'", 163: "b'\\xa3'",
            164: "b'\\xa4'", 165: "b'\\xa5'", 166: "b'\\xa6'", 167: "b'\\xa7'",
            168: "b'\\xa8'", 169: "b'\\xa9'", 170: "b'\\xaa'", 171: "b'\\xab'",
            172: "b'\\xac'", 173: "b'\\xad'", 174: "b'\\xae'", 175: "b'\\xaf'",
            176: "b'\\xb0'", 177: "b'\\xb1'", 178: "b'\\xb2'", 179: "b'\\xb3'",
            180: "b'\\xb4'", 181: "b'\\xb5'", 182: "b'\\xb6'", 183: "b'\\xb7'",
            184: "b'\\xb8'", 185: "b'\\xb9'", 186: "b'\\xba'", 187: "b'\\xbb'",
            188: "b'\\xbc'", 189: "b'\\xbd'", 190: "b'\\xbe'", 191: "b'\\xbf'",
            192: "b'\\xc0'", 193: "b'\\xc1'", 194: "b'\\xc2'", 195: "b'\\xc3'",
            196: "b'\\xc4'", 197: "b'\\xc5'", 198: "b'\\xc6'", 199: "b'\\xc7'",
            200: "b'\\xc8'", 201: "b'\\xc9'", 202: "b'\\xca'", 203: "b'\\xcb'",
            204: "b'\\xcc'", 205: "b'\\xcd'", 206: "b'\\xce'", 207: "b'\\xcf'",
            208: "b'\\xd0'", 209: "b'\\xd1'", 210: "b'\\xd2'", 211: "b'\\xd3'",
            212: "b'\\xd4'", 213: "b'\\xd5'", 214: "b'\\xd6'", 215: "b'\\xd7'",
            216: "b'\\xd8'", 217: "b'\\xd9'", 218: "b'\\xda'", 219: "b'\\xdb'",
            220: "b'\\xdc'", 221: "b'\\xdd'", 222: "b'\\xde'", 223: "b'\\xdf'",
            224: "b'\\xe0'", 225: "b'\\xe1'", 226: "b'\\xe2'", 227: "b'\\xe3'",
            228: "b'\\xe4'", 229: "b'\\xe5'", 230: "b'\\xe6'", 231: "b'\\xe7'",
            232: "b'\\xe8'", 233: "b'\\xe9'", 234: "b'\\xea'", 235: "b'\\xeb'",
            236: "b'\\xec'", 237: "b'\\xed'", 238: "b'\\xee'", 239: "b'\\xef'",
            240: "b'\\xf0'", 241: "b'\\xf1'", 242: "b'\\xf2'", 243: "b'\\xf3'",
            244: "b'\\xf4'", 245: "b'\\xf5'", 246: "b'\\xf6'", 247: "b'\\xf7'",
            248: "b'\\xf8'", 249: "b'\\xf9'", 250: "b'\\xfa'", 251: "b'\\xfb'",
            252: "b'\\xfc'", 253: "b'\\xfd'", 254: "b'\\xfe'", 255: "b'\\xff'",

        }
        for c in range(0, 255):
            self.assertEqual("{:02x} {}".format(c, expected_results[c]),
                             boofuzz.helpers.hex_to_hexstr(bytes(chr(c), 'latin-1'))
                             )


class TestFuzzLoggerText(unittest.TestCase):
    def setUp(self):
        self.virtual_file = StringIO.StringIO()
        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file)
        self.some_test_case_id = "some test case id"
        self.some_test_case_name = "some test case name"
        self.some_test_case_index = 3
        self.some_test_step_msg = "Test!!!"
        self.some_log_check_msg = "logging"
        self.some_log_info_msg = "information"
        self.some_log_fail_msg = "broken"
        self.some_log_pass_msg = "it works so far!"
        self.some_log_error_msg = "D:"

        self.some_recv_data = bytes('A B C', 'ascii')
        self.some_send_data = bytes('123', 'ascii')

    def test_open_test_case(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
        Then: open_test_case logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())

    def test_open_test_step(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
        Then: open_test_case logs as expected.
         and: open_test_step logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.open_test_step(self.some_test_step_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_test_step_msg in self.virtual_file.readline())

    def test_log_check(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with some description.
        Then: open_test_case logs as expected.
         and: log_check logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_check(self.some_log_check_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_log_check_msg in self.virtual_file.readline())

    def test_log_error(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_error with some description.
        Then: open_test_case logs as expected.
         and: log_error logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_error(self.some_log_error_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_log_error_msg in self.virtual_file.readline())

    def test_log_recv(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(fuzz_logger_text.DEFAULT_HEX_TO_STR(self.some_recv_data) in self.virtual_file.readline())

    def test_log_send(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with some data.
        Then: open_test_case logs as expected.
         and: log_send logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_send(self.some_send_data)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(str(len(self.some_send_data)) in self.virtual_file.readline())

    def test_log_info(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with some description.
        Then: open_test_case logs as expected.
         and: log_info logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_info(self.some_log_info_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_log_info_msg in self.virtual_file.readline())

    def test_log_fail(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with some description.
        Then: open_test_case logs as expected.
         and: log_fail logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_fail(self.some_log_fail_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_log_fail_msg in self.virtual_file.readline())

    def test_log_pass(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with some description.
        Then: open_test_case logs as expected.
         and: log_pass logs as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_pass(self.some_log_pass_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_log_pass_msg in self.virtual_file.readline())

    def test_open_test_case_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with an empty string.
        Then: open_test_case logs with a zero-length test case id.
        """
        # When
        self.logger.open_test_case('', self.some_test_case_name, self.some_test_case_index)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue('case' in self.virtual_file.readline().lower())

    def test_open_test_step_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with an empty string.
        Then: open_test_step logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.open_test_step('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue('step' in self.virtual_file.readline().lower())

    def test_log_check_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_check with an empty string.
        Then: log_check logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_check('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue('check' in self.virtual_file.readline().lower())

    def test_log_error_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_error with an empty string.
        Then: log_error logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_error('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue('error' in self.virtual_file.readline().lower())

    def test_log_recv_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with an empty buffer.
        Then: log_recv logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_recv(bytes('', 'ascii'))

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(fuzz_logger_text.DEFAULT_HEX_TO_STR(bytes('', 'ascii')) in self.virtual_file.readline())

    def test_log_send_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_send with an empty buffer.
        Then: log_send logs with zero-length data.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_send(bytes('', 'ascii'))

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(str(len(bytes('', 'ascii'))) in self.virtual_file.readline().lower())

    def test_log_info_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_info with an empty string.
        Then: log_info logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_info('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue('info' in self.virtual_file.readline().lower())

    def test_log_fail_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_fail with no argument.
        Then: log_fail logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_fail('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue('fail' in self.virtual_file.readline().lower())

    def test_log_pass_empty(self):
        """
        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_pass with no argument.
        Then: log_pass logs with a zero-length description.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_pass('')

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        assert 'ok' in self.virtual_file.readline().lower()

    def test_several(self):
        """
        Verify that log functions work consistently in series.

        Given: FuzzLoggerText with a virtual file handle.
        When: Calling open_test_case with some test_case_id.
         and: Calling open_test_step with some description.
         and: Calling log_recv with some data.
         and: Calling log_send with some data.
         and: Calling log_info with some description.
         and: Calling log_check with some description.
         and: Calling log_fail with some description.
         and: Calling log_pass with some description.
         and: Calling log_error with some description.
        Then: All methods log as expected.
        """
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.open_test_step(self.some_test_step_msg)
        self.logger.log_recv(self.some_recv_data)
        self.logger.log_send(self.some_send_data)
        self.logger.log_info(self.some_log_info_msg)
        self.logger.log_check(self.some_log_check_msg)
        self.logger.log_fail(self.some_log_fail_msg)
        self.logger.log_pass(self.some_log_pass_msg)
        self.logger.log_error(self.some_log_error_msg)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(self.some_test_step_msg in self.virtual_file.readline())
        self.assertTrue(self.some_recv_data in self.virtual_file.readline())
        self.assertTrue(str(len(self.some_send_data)) in self.virtual_file.readline())
        self.assertTrue(self.some_log_info_msg in self.virtual_file.readline())
        self.assertTrue(self.some_log_check_msg in self.virtual_file.readline())
        self.assertTrue(self.some_log_fail_msg in self.virtual_file.readline())
        self.assertTrue(self.some_log_pass_msg in self.virtual_file.readline())
        self.assertTrue(self.some_log_error_msg in self.virtual_file.readline())

    def test_hex_to_str_function(self):
        """
        Verify that the UUT uses the custom hex_to_str function, if provided.

        Given: FuzzLoggerText with a virtual file handle and custom hex_to_str
               function.
        When: Calling open_test_case with some test_case_id.
         and: Calling log_recv with some data.
        Then: open_test_case logs as expected.
         and: log_recv logs as expected, using the custom hex_to_str function.
        """

        # Given
        def hex_to_str(hex_data):
            return hex_data.decode()

        self.logger = fuzz_logger_text.FuzzLoggerText(file_handle=self.virtual_file,
                                                      bytes_to_str=hex_to_str)
        # When
        self.logger.open_test_case(self.some_test_case_id, self.some_test_case_name, self.some_test_case_index)
        self.logger.log_recv(self.some_recv_data)

        # Then
        self.virtual_file.seek(0)
        self.assertTrue(self.some_test_case_id in self.virtual_file.readline())
        self.assertTrue(hex_to_str(self.some_recv_data) in self.virtual_file.readline())


if __name__ == '__main__':
    unittest.main()
