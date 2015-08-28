import unittest
from sulley import itarget_connection
from sulley.serial_connection_generic import SerialConnectionGeneric
import random


class MockSerialConnection(itarget_connection.ITargetConnection):
    def __init__(self):
        self.close_called = False
        self.open_called = False
        self.send_data_list = []
        self.send_return_queue = []

    def close(self):
        """
        Close connection.

        :return: None
        """
        self.close_called = True

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self.open_called = True

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data. bytes('') if no data is received.
        """
        raise NotImplementedError

    def send(self, data):
        """
        Send data to the target.

        :param data: Data to send.

        :return: None
        """
        self.send_data_list.append(data)
        if len(self.send_return_queue) > 0:
            return self.send_return_queue.pop(0)
        else:
            return len(data)


class TestSerialConnection(unittest.TestCase):
    def setUp(self):
        self.mock = MockSerialConnection()

    def test_open(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.open().
        Then: MockSerialConnection.open() is called.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        uut.open()
        self.assertTrue(self.mock.open_called)

    def test_close(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.close().
        Then: MockSerialConnection.close() is called.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        uut.close()
        self.assertTrue(self.mock.close_called)

    def test_send_basic(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.send(data)
         and: MockSerialConnection.send() returns len(data).
        Then: Verify MockSerialConnection.send() was called only once.
         and: Verify MockSerialConnection.send() received the expected data.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = "ABCDEFG"
        uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 1)
        self.assertEqual(self.mock.send_data_list[0], "ABCDEFG")

    def test_send_multiple(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.send(data) with 9 bytes.
         and: MockSerialConnection.send() returns: 0, 0, 1, 2, 3, 2, 1.
        Then: Verify MockSerialConnection.send() was called exactly 7 times.
         and: Verify MockSerialConnection.send() received the expected data each time.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = "123456789"
        self.mock.send_return_queue = [0, 0, 1, 2, 3, 2, 1]
        uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 7)
        self.assertEqual(self.mock.send_data_list, ["123456789",
                                                    "123456789",
                                                    "123456789",
                                                    "23456789",
                                                    "456789",
                                                    "789",
                                                    "9"])

    def test_send_off_by_one(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.send(data) with 9 bytes.
         and: MockSerialConnection.send() returns: 8, 1.
        Then: Verify MockSerialConnection.send() was called exactly 2 times.
         and: Verify MockSerialConnection.send() received the expected data each time.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = "123456789"
        self.mock.send_return_queue = [8, 1]
        uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 2)
        self.assertEqual(self.mock.send_data_list, ["123456789",
                                                    "9"])

    def test_send_one_byte(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.send(data) with 1 byte.
         and: MockSerialConnection.send() returns: 0, 1.
        Then: Verify MockSerialConnection.send() was called exactly 2 times.
         and: Verify MockSerialConnection.send() received the expected data each time.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = "1"
        self.mock.send_return_queue = [0, 1]
        uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 2)
        self.assertEqual(self.mock.send_data_list, ["1",
                                                    "1"])

    def test_send_many(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.

        When: Calling SerialConnectionGeneric.send(data) with 9 bytes.
         and: MockSerialConnection.send() returns: 0, 500 times, followed by len(data).

        Then: Verify MockSerialConnection.send() was called exactly 501 times.
         and: Verify MockSerialConnection.send() received the expected data each time.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = "123456789"
        self.mock.send_return_queue = [0]*500 + [len(data)]
        uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 501)
        self.assertEqual(self.mock.send_data_list, ["123456789"]*501)

    def test_send_zero_bytes(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection.
        When: Calling SerialConnectionGeneric.send(data) with 0 bytes.
         and: MockSerialConnection.send() set to return len(data).
        Then: Verify MockSerialConnection.send() was called either 0 or 1 times.
         and: Verify MockSerialConnection.send() received 0 bytes, if anything.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        data = ""
        self.mock.send_return_queue = [0, 1]
        uut.send(data=data)
        # Then
        self.assertLessEqual(len(self.mock.send_data_list), 1)
        if len(self.mock.send_data_list) == 0:
            self.assertEqual(self.mock.send_data_list, [])
        else:
            self.assertEqual(self.mock.send_data_list, [""])


if __name__ == '__main__':
    unittest.main()
