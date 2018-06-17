from __future__ import print_function
import sys
import datetime
import csv
import sqlite3

from . import helpers
from . import ifuzz_logger_backend
from . import test_case_data
from . import test_step_data


def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    :param input_bytes: Arbitrary bytes.

    :return: Printable string.
    """
    return helpers.hex_str(input_bytes)


DEFAULT_HEX_TO_STR = hex_to_hexstr


def get_time_stamp():
    s = datetime.datetime.utcnow().isoformat()
    return s


class FuzzLoggerDb(ifuzz_logger_backend.IFuzzLoggerBackend):
    """Log fuzz data in a sqlite database file.

    Args:
        bytes_to_str (function): Function that converts sent/received bytes data to string for logging.
    """

    def __init__(self, bytes_to_str=DEFAULT_HEX_TO_STR):
        timestamp = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(':', '-')
        self._databaes_connection = sqlite3.connect('boofuzz-run-{0}.db'.format(timestamp), check_same_thread=False)
        self._db_cursor = self._databaes_connection.cursor()
        self._db_cursor.execute('''CREATE TABLE cases (name text, number integer, timestamp TEXT)''')
        self._db_cursor.execute('''CREATE TABLE steps (test_case_index integer, type text, description text, data blob, timestamp TEXT)''')

        self._format_raw_bytes = bytes_to_str
        self._current_test_case_index = None

    def get_test_case_data(self, index):
        c = self._databaes_connection.cursor()
        test_case_row = next(c.execute('''SELECT * FROM cases WHERE number=?''', [index]))
        rows = c.execute('''SELECT * FROM steps WHERE test_case_index=?''', [index])
        steps = []
        for row in rows:
            steps.append(test_step_data.TestStepData(type=row[1], description=row[2], data=row[3], timestamp=row[4]))
        return test_case_data.TestCaseData(name=test_case_row[0], index=test_case_row[1], timestamp=test_case_row[2], steps=steps)

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._db_cursor.execute('''INSERT INTO cases VALUES(?, ?, ?)''', [name, index, helpers.get_time_stamp()])
        self._current_test_case_index = index


    def open_test_step(self, description):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'step', description, b'', helpers.get_time_stamp()])

    def log_check(self, description):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'check', description, b'', helpers.get_time_stamp()])

    def log_error(self, description):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'error', description, b'', helpers.get_time_stamp()])

    def log_recv(self, data):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'receive', u'', buffer(data), helpers.get_time_stamp()])

    def log_send(self, data):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'send', u'', buffer(data), helpers.get_time_stamp()])

    def log_info(self, description):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'info', description, b'', helpers.get_time_stamp()])

    def log_fail(self, description=""):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'fail', description, b'', helpers.get_time_stamp()])

    def log_pass(self, description=""):
        self._db_cursor.execute('''INSERT INTO steps VALUES(?, ?, ?, ?, ?)''', [self._current_test_case_index, 'pass', description, b'', helpers.get_time_stamp()])

    def _print_log_msg(self, msg):
        time_stamp = get_time_stamp()
        self._csv_handle.writerow([time_stamp] + msg)
