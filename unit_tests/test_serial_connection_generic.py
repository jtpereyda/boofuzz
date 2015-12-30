import unittest
from boofuzz import iserial_like
from boofuzz.serial_connection import SerialConnection
import time


class MockSerial(iserial_like.ISerialLike):
    """
    Mock ISerialLike class.
    Methods include code for unit testing. See each method for details.
    """

    def __init__(self):
        self.close_called = False
        self.open_called = False
        self.send_data_list = []
        self.send_return_queue = []
        self.recv_max_bytes_lengths = []
        self.recv_return_queue = []
        self.recv_return_nothing_by_default = False
        self.recv_wait_times = []

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

        Mock method:
         - Waits some amount of time according to self.recv_wait_times
         - Appends max_bytes to self.recv_max_bytes_lengths
         - Returns based on self.recv_return_queue
            * If empty, returns b'' if self.recv_return_nothing_by_default is True, or
              b'0'*max_bytes otherwise.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data. bytes('') if no data is received.
        """
        # Wait if needed
        if len(self.recv_wait_times) > 0:
            time.sleep(self.recv_wait_times.pop(0))

        # Save argument
        self.recv_max_bytes_lengths.append(max_bytes)

        # Return data
        if len(self.recv_return_queue) > 0:
            return self.recv_return_queue.pop(0)
        elif self.recv_return_nothing_by_default:
            return b''
        else:
            return b'0' * max_bytes

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
        self.mock = MockSerial()
        self.uut = SerialConnection()
        self.uut._connection = self.mock

    def test_open(self):
        """
        Given: A SerialConnection using MockSerial.
        When: Calling SerialConnection.open().
        Then: MockSerial.open() is called.
        """
        self.uut.open()
        self.assertTrue(self.mock.open_called)

    def test_close(self):
        """
        Given: A SerialConnection using MockSerial.
        When: Calling SerialConnection.close().
        Then: MockSerial.close() is called.
        """
        self.uut.close()
        self.assertTrue(self.mock.close_called)

    ###########################################################################
    # Send tests
    ###########################################################################
    def test_send_basic(self):
        """
        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data)
        and: MockSerial.send() returns len(data).

        Then: Verify MockSerial.send() was called only once.
        and: Verify MockSerial.send() received the expected data.
        """
        # When
        data = b'ABCDEFG'
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 1)
        self.assertEqual(self.mock.send_data_list[0], b'ABCDEFG')

    def test_send_return_none(self):
        """
        Verify that MockSerial.send() is called again when it returns None.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 10 bytes.
        and: MockSerial.send() returns: None, 10.

        Then: Verify MockSerial.send() was called exactly 2 times.
        and: Verify MockSerial.send() received the expected data each time.
        """
        # When
        data = b'123456789A'
        self.mock.send_return_queue = [None, 10]
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 2)
        self.assertEqual(self.mock.send_data_list, [b'123456789A',
                                                    b'123456789A'])

    def test_send_multiple(self):
        """
        Verify that MockSerial.send() is called repeatedly until it sends all the data.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 9 bytes.
        and: MockSerial.send() returns: 0, None, 0, 1, 2, 3, 2, 1.

        Then: Verify MockSerial.send() was called exactly 7 times.
        and: Verify MockSerial.send() received the expected data each time.
        """
        # When
        data = b'123456789'
        self.mock.send_return_queue = [0, None, 0, 1, 2, 3, 2, 1]
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 8)
        self.assertEqual(self.mock.send_data_list, [b'123456789',
                                                    b'123456789',
                                                    b'123456789',
                                                    b'123456789',
                                                    b'23456789',
                                                    b'456789',
                                                    b'789',
                                                    b'9'])

    def test_send_off_by_one(self):
        """
        Verify that MockSerial.send() is called again when it sends all but 1 byte.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 9 bytes.
        and: MockSerial.send() returns: 8, 1.

        Then: Verify MockSerial.send() was called exactly 2 times.
        and: Verify MockSerial.send() received the expected data each time.
        """
        # When
        data = b'123456789'
        self.mock.send_return_queue = [8, 1]
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 2)
        self.assertEqual(self.mock.send_data_list, [b'123456789',
                                                    b'9'])

    def test_send_one_byte(self):
        """
        Verify that MockSerial.send() is called again when it returns 0 after being given 1 byte.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 1 byte.
        and: MockSerial.send() returns: 0, 1.

        Then: Verify MockSerial.send() was called exactly 2 times.
        and: Verify MockSerial.send() received the expected data each time.
        """
        # When
        data = b'1'
        self.mock.send_return_queue = [0, 1]
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 2)
        self.assertEqual(self.mock.send_data_list, [b'1',
                                                    b'1'])

    def test_send_many(self):
        """
        Verify that send works properly when MockSerial.send() sends 1 byte at a time.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 9 bytes.
        and: MockSerial.send() returns: 0, 500 times, followed by len(data).

        Then: Verify MockSerial.send() was called exactly 501 times.
        and: Verify MockSerial.send() received the expected data each time.
        """
        # When
        data = b'123456789'
        self.mock.send_return_queue = [0] * 500 + [len(data)]
        self.uut.send(data=data)
        # Then
        self.assertEqual(len(self.mock.send_data_list), 501)
        self.assertEqual(self.mock.send_data_list, [b'123456789'] * 501)

    def test_send_zero_bytes(self):
        """
        Verify that send() doesn't fail when given 0 bytes.

        Given: A SerialConnection using MockSerial.

        When: Calling SerialConnection.send(data) with 0 bytes.
        and:  MockSerial.send() set to return len(data).

        Then: Verify MockSerial.send() was called either 0 or 1 times.
        and:  Verify MockSerial.send() received 0 bytes, if anything.
        """
        # When
        data = b''
        self.mock.send_return_queue = [0, 1]
        self.uut.send(data=data)
        # Then
        self.assertLessEqual(len(self.mock.send_data_list), 1)
        if len(self.mock.send_data_list) == 0:
            self.assertEqual(self.mock.send_data_list, [])
        else:
            self.assertEqual(self.mock.send_data_list, [b''])

    ###########################################################################
    # Receive tests
    ###########################################################################
    def test_recv_simple(self):
        """
        Verify that recv() works in the normal case.

        Given: A SerialConnection using MockSerial,
               with no timeout/message_separator_time/content_checker.

        When: User calls SerialConnection.recv.
          and: MockSerial.recv set to return data of length max_bytes.

        Then: SerialConnection calls MockSerial.recv exactly once.
         and: SerialConnection.recv returns exactly what MockSerial.recv returned.
        """
        # When
        self.mock.recv_return_queue = [b'0123456']
        data = self.uut.recv(max_bytes=7)
        # Then
        self.assertEqual(self.mock.recv_max_bytes_lengths, [7])
        self.assertEqual(data, b'0123456')

    def test_recv_max_bytes_only(self):
        """
        Verify that recv() calls MockSerial.recv() repeatedly until it gets max_bytes of data.

        Given: A SerialConnection using MockSerial,
               with no timeout/message_separator_time/content_checker.

        When: User calls SerialConnection.recv(10).
          and: MockSerial.recv set to return 0, 0, 0, 1, 2, 3, 4 bytes.

        Then: SerialConnection calls MockSerial.recv exactly 7 times,
              with max_bytes decreasing as appropriate.
         and: SerialConnection.recv returns the concatenation of MockSerial.recv() return values.
        """
        # When
        self.mock.recv_return_queue = [b'', b'', b'', b'1', b'22', b'123', b'1234']
        data = self.uut.recv(max_bytes=10)
        # Then
        self.assertEqual(self.mock.recv_max_bytes_lengths, [10, 10, 10, 10, 9, 7, 4])
        self.assertEqual(data, b'1221231234')

    def test_recv_timeout(self):
        """
        Verify that recv() returns partial messages after the timeout expires.

        Given: A SerialConnection using MockSerial,
               with timeout set to a smallish value.

        When: User calls SerialConnection.recv(n) several times with different values of n.
          and: MockSerial.recv set to return a single message, then repeatedly return nothing.

        Then: SerialConnection.recv calls MockSerial.recv at least once.
         and: SerialConnection.recv returns the MockSerial.recv() return value after the timeout.

        Note: Timeout functionality is tested, but not the precise timing.
        """
        self.uut = SerialConnection(timeout=.001)  # 1ms
        self.uut._connection = self.mock

        # n == 1
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'']
        data = self.uut.recv(max_bytes=1)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'')

        # n == 2
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'1']
        data = self.uut.recv(max_bytes=2)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'1')

        # n == 3, len(data) == 1
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'1']
        data = self.uut.recv(max_bytes=5)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'1')

        # n == 3, len(data) == 2
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'12']
        data = self.uut.recv(max_bytes=3)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'12')

        # # n == 2**16, len(data) == 2**16 - 1
        # self.mock.recv_return_nothing_by_default = True
        # self.mock.recv_return_queue = [b'\0'] * (2**16 - 1)
        # data = uut.recv(max_bytes=2**16)
        # self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        # self.assertEqual(data, [b'\0'] * (2**16 - 1))

    def test_recv_message_separator_time(self):
        """
        Verify that message_separator_time works correctly.
        Receive a message over time t, where t > message_separator_time, and each part of the message is delayed by
        t' < message_separator_time.

        Given: A SerialConnection using MockSerial,
          and: timeout set to 60ms.
          and: message_separator_time set 20ms

        When: User calls SerialConnection.recv(max_bytes=60).
         and: MockSerial.recv set to return increasing bytes.
         and: MockSerial.recv set to delay very briefly on each call (0.001ms (1 microsecond)).

        Then: SerialConnection.recv calls MockSerial.recv multiple times (more than 2).
         and: SerialConnection.recv returns data with multiple bytes (more than 2).
        """
        # Given
        self.uut = SerialConnection(timeout=.060, message_separator_time=.020)
        self.uut._connection = self.mock

        # When
        self.mock.recv_return_queue = [b'1'] * 60
        self.mock.recv_wait_times = [0.000001] * 60
        data = self.uut.recv(max_bytes=60)

        # Then
        self.assertGreater(len(self.mock.recv_max_bytes_lengths), 2)
        self.assertGreater(len(data), 2)

    def test_recv_message_separator_time_2(self):
        """
        Verify that message_separator_time works correctly.
        Receive a message that times out with message_separator_time, but which would not time out with only a timeout.

        Given: A SerialConnection using MockSerial,
          and: timeout set to 60ms.
          and: message_separator_time set 20ms

        When: User calls SerialConnection.recv(60).
         and: MockSerial.recv set to return 1 byte, then 1 byte, then 58 bytes.
         and: MockSerial.recv set to delay 1ms, then 40ms, then 1ms.

        Then: SerialConnection.recv calls MockSerial.recv twice.
         and: SerialConnection.recv returns only the first two bytes.
        """
        # Given
        self.uut = SerialConnection(timeout=.060, message_separator_time=.020)
        self.uut._connection = self.mock

        # When
        self.mock.recv_return_queue = [b'1', b'2', b'3' * 58]
        self.mock.recv_wait_times = [.001, .040, .001]
        data = self.uut.recv(max_bytes=60)

        # Then
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 2)
        self.assertEqual(data, b'12')

    def test_recv_message_content_checker(self):
        """
        Verify that content_checker is used correctly.
        The content_checker indicates how much of a message is valid, if any.
        Verify behavior when the content_checker consumes a part of the buffer, the full buffer, and then part of it
        again.

        Given: A SerialConnection using MockSerial,
          and: timeout set to 100ms.
          and: message_separator_time set 20ms
          and: content_checker set to a function that returns 0, 3, 0, 5, 0, 3

        When: User calls SerialConnection.recv(100) 3 times.
         and: MockSerial.recv set to return 2 bytes repeatedly.

        Then: SerialConnection.recv calls MockSerial.recv 6 times.
         and: SerialConnection.recv returns only the first 3 bytes, then the next 5 bytes, then the next 3.
        """

        # Given
        # PyUnusedLocal suppression: args/kwargs make the method callable by SerialConnection, but are not used.
        # noinspection PyUnusedLocal
        def test_checker(*args, **kwargs):
            """
            :param args:   Ignored. Makes method callable with arguments.
            :param kwargs: Ignored. Makes method callable with arguments.

            :return: 0, 3, 0, 5, 0, 3, 0, 0...
            """
            if not hasattr(test_checker, "counter"):
                test_checker.counter = 0

            test_checker.counter += 1

            if test_checker.counter == 2:
                return 3
            elif test_checker.counter == 4:
                return 5
            elif test_checker.counter == 6:
                return 3
            else:
                return 0

        self.uut = SerialConnection(timeout=.100,
                                    message_separator_time=.020,
                                    content_checker=test_checker)
        self.uut._connection = self.mock

        # When
        self.mock.recv_return_queue = [b'12', b'34', b'56', b'78', b'9A', b'BC']

        data = self.uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 2)
        self.assertEqual(data, b'123')

        data = self.uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 4)
        self.assertEqual(data, b'45678')

        data = self.uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 6)
        self.assertEqual(data, b'9AB')


if __name__ == '__main__':
    unittest.main()
