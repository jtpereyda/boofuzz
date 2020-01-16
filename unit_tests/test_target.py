import time
import unittest

from boofuzz.connections import ITargetConnection
from boofuzz import Target, TimeRepeater, CountRepeater


class MockCountConnection(ITargetConnection):
    def __init__(self):
        self.count = 0

    def close(self):
        pass

    def open(self):
        pass

    def recv(self, max_bytes):
        pass

    def send(self, data):
        self.count += 1

    @property
    def info(self):
        pass


class MockTimeConnection(ITargetConnection):
    def __init__(self):
        self.first = None
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
        self.last = time.time()

    @property
    def info(self):
        pass


class TestTarget(unittest.TestCase):
    def test_count_repeater(self):
        repeater = CountRepeater(5)
        connection = MockCountConnection()
        target = Target(connection, repeater=repeater)

        target.send(b"This is a test")

        self.assertEqual(repeater.count, connection.count)

    def test_time_repeater(self):
        repeater = TimeRepeater(5)
        connection = MockTimeConnection()
        target = Target(connection, repeater=repeater)

        target.send(b"This is a test")
        self.assertLessEqual(connection.last - connection.first, repeater.duration)
