from __future__ import print_function

import collections
import datetime
import sqlite3
import sys

import six

from . import data_test_case, data_test_step, exception, helpers, ifuzz_logger_backend

# fixup for buffer in python 3
if sys.version_info.major > 2:
    buffer = memoryview


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
    """Log fuzz data in a sqlite database file."""

    def __init__(self, db_filename, num_log_cases=0):
        self._database_connection = sqlite3.connect(db_filename, check_same_thread=False)
        self._db_cursor = self._database_connection.cursor()
        self._db_cursor.execute("""CREATE TABLE cases (name text, number integer, timestamp TEXT)""")
        self._db_cursor.execute(
            """CREATE TABLE steps (test_case_index integer, type text, description text, data blob,
                                   timestamp TEXT, is_truncated BOOLEAN)"""
        )

        self._current_test_case_index = 0

        self._queue = collections.deque([])  # Queue that holds last n test cases before commiting
        self._queue_max_len = num_log_cases
        self._fail_detected = False
        self._log_first_case = True
        self._data_truncate_length = 512

    def get_test_case_data(self, index):
        c = self._database_connection.cursor()
        try:
            test_case_row = next(c.execute("""SELECT * FROM cases WHERE number=?""", [index]))
        except StopIteration:
            return None
        rows = c.execute("""SELECT * FROM steps WHERE test_case_index=?""", [index])
        steps = []
        for row in rows:
            data = row[3]
            # Little hack since BLOB becomes type buffer in py2 and bytes in py3
            # At the end, data will be equivalent types: bytes in py3 and str in py2
            try:
                if isinstance(data, buffer):
                    data = str(data)
            except NameError as e:
                if "buffer" in str(e):  # buffer type does not exist in py3
                    pass
                else:
                    raise
            steps.append(
                data_test_step.DataTestStep(
                    type=row[1], description=row[2], data=data, timestamp=row[4], truncated=row[5]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row[0], index=test_case_row[1], timestamp=test_case_row[2], steps=steps
        )

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._queue.append(["INSERT INTO cases VALUES(?, ?, ?);\n", name, index, helpers.get_time_stamp()])
        self._current_test_case_index = index

    def open_test_step(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "step",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )

    def log_check(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "check",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )

    def log_error(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "error",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )
        self._fail_detected = True
        self._write_log()

    def log_recv(self, data):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "receive",
                u"",
                buffer(data),
                helpers.get_time_stamp(),
                False,
            ]
        )

    def log_send(self, data):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "send",
                u"",
                buffer(data),
                helpers.get_time_stamp(),
                False,
            ]
        )

    def log_info(self, description):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "info",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )

    def log_fail(self, description=""):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "fail",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )
        self._fail_detected = True

    def log_pass(self, description=""):
        self._queue.append(
            [
                "INSERT INTO steps VALUES(?, ?, ?, ?, ?, ?);\n",
                self._current_test_case_index,
                "pass",
                description,
                b"",
                helpers.get_time_stamp(),
                False,
            ]
        )

    def close_test_case(self):
        self._write_log(force=False)

    def close_test(self):
        self._write_log(force=True)

    def _write_log(self, force=False):
        if len(self._queue) > 0:
            if self._queue_max_len > 0:
                while (
                    self._current_test_case_index - next(x for x in self._queue[0] if isinstance(x, six.integer_types))
                ) >= self._queue_max_len:
                    self._queue.popleft()
            else:
                force = True

            if force or self._fail_detected or self._log_first_case:
                for query in self._queue:
                    # abbreviate long entries first
                    if not self._fail_detected:
                        self._truncate_send_recv(query)
                    self._db_cursor.execute(query[0], query[1:])
                self._queue.clear()
                self._database_connection.commit()
                self._log_first_case = False
                self._fail_detected = False

    def _truncate_send_recv(self, query):
        if query[2] in ["send", "recv"] and len(query[4]) > self._data_truncate_length:
            query[6] = True
            query[4] = buffer(query[4][: self._data_truncate_length])


class FuzzLoggerDbReader(object):
    """Read fuzz data saved using FuzzLoggerDb

    Args:
        db_filename (str): Name of database file to read.
    """

    def __init__(self, db_filename):
        self._database_connection = sqlite3.connect(db_filename, check_same_thread=False)
        self._db_cursor = self._database_connection.cursor()

    def get_test_case_data(self, index):
        c = self._db_cursor
        try:
            test_case_row = next(c.execute("""SELECT * FROM cases WHERE number=?""", [index]))
        except StopIteration:
            raise exception.BoofuzzNoSuchTestCase()

        rows = c.execute("""SELECT * FROM steps WHERE test_case_index=?""", [index])
        steps = []
        for row in rows:
            data = row[3]
            # Little hack since BLOB becomes type buffer in py2 and bytes in py3
            # At the end, data will be equivalent types: bytes in py3 and str in py2
            try:
                if isinstance(data, buffer):
                    data = str(data)
            except NameError as e:
                if "buffer" in str(e):  # buffer type does not exist in py3
                    pass
                else:
                    raise
            steps.append(
                data_test_step.DataTestStep(
                    type=row[1], description=row[2], data=data, timestamp=row[4], truncated=row[5]
                )
            )
        return data_test_case.DataTestCase(
            name=test_case_row[0], index=test_case_row[1], timestamp=test_case_row[2], steps=steps
        )

    def query(self, query, params=None):
        if params is None:
            params = []
        c = self._db_cursor
        return c.execute(query, params)

    @property
    def failure_map(self):
        c = self._db_cursor
        failure_steps = c.execute('''SELECT * FROM steps WHERE type="fail"''')

        failure_map = collections.defaultdict(list)
        for step in failure_steps:
            failure_map[step[0]].append(step[2])
        return failure_map
