import pytest
import sys
import time
import unittest

from boofuzz import CountRepeater, Target, TimeRepeater
from boofuzz.connections import ITargetConnection


class MockCountConnection(ITargetConnection):
    def __init__(self):
        self.count = 0
        self.first = None
        self.second = None

    def close(self):
        pass

    def open(self):
        pass

    def recv(self, max_bytes):
        pass

    def send(self, data):
        self.count += 1
        if self.first is None:
            self.first = time.time()
        elif self.second is None:
            self.second = time.time()

    @property
    def info(self):
        return


class MockTimeConnection(ITargetConnection):
    def __init__(self):
        self.first = None
        self.second = None
        self.last = None

    def close(self):
        pass

    def open(self):
        pass

    def recv(self, max_bytes):
        pass

    def send(self, data):
        if self.first is None:
            self.first = time.time()
        elif self.second is None:
            self.second = time.time()
        self.last = time.time()

    @property
    def info(self):
        return


class TestTarget(unittest.TestCase):
    SLEEP_TIME = 0.01

    @pytest.mark.xfail(sys.platform == "win32", reason="known broken, fixed in pull #442")
    def test_count_repeater(self):
        repeater = CountRepeater(count=5, sleep_time=self.SLEEP_TIME)
        connection = MockCountConnection()
        target = Target(connection, repeater=repeater)

        target.send(b"This is a test")

        self.assertEqual(repeater.count, connection.count)
        self.assertGreaterEqual(connection.second - connection.first, self.SLEEP_TIME)
        with self.assertRaises(ValueError):
            CountRepeater(count=0)

    @pytest.mark.xfail(sys.platform == "win32", reason="known broken, fixed in pull #442")
    def test_time_repeater(self):
        repeater = TimeRepeater(duration=0.05, sleep_time=self.SLEEP_TIME)
        connection = MockTimeConnection()
        target = Target(connection, repeater=repeater)

        target.send(b"This is a test")

        self.assertLessEqual(connection.last - connection.first, repeater.duration)
        self.assertGreaterEqual(connection.second - connection.first, self.SLEEP_TIME)
        with self.assertRaises(ValueError):
            TimeRepeater(duration=0)
