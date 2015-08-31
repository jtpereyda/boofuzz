import unittest
from sulley import itarget_connection
from sulley.serial_connection_generic import SerialConnectionGeneric
import time


class MockSerialConnection(itarget_connection.ITargetConnection):
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
            return [0]*max_bytes

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

    ###########################################################################
    # Send tests
    ###########################################################################
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
        and:  MockSerialConnection.send() set to return len(data).

        Then: Verify MockSerialConnection.send() was called either 0 or 1 times.
        and:  Verify MockSerialConnection.send() received 0 bytes, if anything.
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

    ###########################################################################
    # Receive tests
    ###########################################################################
    def test_recv_simple(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection,
               with no timeout/message_separator_time/content_checker.

        When: User calls SerialConnectionGeneric.recv.
          and: MockSerialConnection.recv set to return data of length max_bytes.

        Then: SerialConnectionGeneric calls MockSerialConnection.recv exactly once.
         and: SerialConnectionGeneric.recv returns exactly what MockSerialConnection.recv returned.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        self.mock.recv_return_queue = ["0123456"]
        data = uut.recv(max_bytes=7)
        # Then
        self.assertEqual(self.mock.recv_max_bytes_lengths, [7])
        self.assertEqual(data, "0123456")

    def test_recv_max_bytes_only(self):
        """
        Given: A SerialConnectionGeneric using MockSerialConnection,
               with no timeout/message_separator_time/content_checker.

        When: User calls SerialConnectionGeneric.recv(10).
          and: MockSerialConnection.recv set to return 0, 0, 0, 1, 2, 3, 4 bytes.

        Then: SerialConnectionGeneric calls MockSerialConnection.recv exactly 7 times,
              with max_bytes decreasing as appropriate.
         and: SerialConnectionGeneric.recv returns the concatenation of MockSerialConnection.recv() return values.
        """
        uut = SerialConnectionGeneric(connection=self.mock)
        # When
        self.mock.recv_return_queue = ["", "", "", "1", "22", "123", "1234"]
        data = uut.recv(max_bytes=10)
        # Then
        self.assertEqual(self.mock.recv_max_bytes_lengths, [10, 10, 10, 10, 9, 7, 4])
        self.assertEqual(data, b"1221231234")

    def test_recv_timeout(self):
        """
        Verify that recv() returns partial messages after the timeout expires.

        Given: A SerialConnectionGeneric using MockSerialConnection,
               with timeout set to a smallish value.

        When: User calls SerialConnectionGeneric.recv(n) several times with different values of n.
          and: MockSerialConnection.recv set to return a single message, then repeatedly return nothing.

        Then: SerialConnectionGeneric.recv calls MockSerialConnection.recv at least once.
         and: SerialConnectionGeneric.recv returns the MockSerialConnection.recv() return value after the timeout.

        Note: Timeout functionality is tested, but not the precise timing.
        """
        uut = SerialConnectionGeneric(connection=self.mock, timeout=.001)  # 1ms

        # n == 1
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'']
        data = uut.recv(max_bytes=1)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'')

        # n == 2
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'1']
        data = uut.recv(max_bytes=2)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'1')

        # n == 3, len(data) == 1
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'1']
        data = uut.recv(max_bytes=5)
        self.assertGreaterEqual(len(self.mock.recv_max_bytes_lengths), 1)
        self.assertEqual(data, b'1')

        # n == 3, len(data) == 2
        self.mock.recv_return_nothing_by_default = True
        self.mock.recv_return_queue = [b'12']
        data = uut.recv(max_bytes=3)
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
        Receive a message over time t > message_separator_time, where each part of the message is delayed by
        t' < message_separator_time.

        Given: A SerialConnectionGeneric using MockSerialConnection,
          and: timeout set to 60ms.
          and: message_separator_time set 20ms

        When: User calls SerialConnectionGeneric.recv(60).
         and: MockSerialConnection.recv set to return increasing bytes.
         and: MockSerialConnection.recv set to delay 1ms on each call.

        Then: SerialConnectionGeneric.recv calls MockSerialConnection.recv more than 20 times.
         and: SerialConnectionGeneric.recv returns data with more than 20 bytes.
        """
        # Given
        uut = SerialConnectionGeneric(connection=self.mock, timeout=.060, message_separator_time=.020)

        # When
        self.mock.recv_return_queue = [b"1"] * 60
        self.mock.recv_wait_times = [.001] * 60
        data = uut.recv(max_bytes=60)

        # Then
        self.assertGreater(len(self.mock.recv_max_bytes_lengths), 20)
        self.assertGreater(len(data), 20)

    def test_recv_message_separator_time_2(self):
        """
        Verify that message_separator_time works correctly.
        Receive a message that times out with message_separator_time, but which would not time out with only a timeout.

        Given: A SerialConnectionGeneric using MockSerialConnection,
          and: timeout set to 60ms.
          and: message_separator_time set 20ms

        When: User calls SerialConnectionGeneric.recv(60).
         and: MockSerialConnection.recv set to return 1 byte, then 1 byte, then 58 bytes.
         and: MockSerialConnection.recv set to delay 1ms, then 40ms, then 1ms.

        Then: SerialConnectionGeneric.recv calls MockSerialConnection.recv twice.
         and: SerialConnectionGeneric.recv returns only the first two bytes.
        """
        # Given
        uut = SerialConnectionGeneric(connection=self.mock, timeout=.060, message_separator_time=.020)

        # When
        self.mock.recv_return_queue = [b"1", b"2", b"3"*58]
        self.mock.recv_wait_times = [.001, .040, .001]
        data = uut.recv(max_bytes=60)

        # Then
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 2)
        self.assertEqual(data, b"12")

    def test_recv_message_content_checker(self):
        """
        Verify that content_checker is used correctly.
        The content_checker indicates how much of a message is valid, if any.
        Verify behavior when the content_checker consumes a part of the buffer, the full buffer, and then part of it
        again.

        Given: A SerialConnectionGeneric using MockSerialConnection,
          and: timeout set to 100ms.
          and: message_separator_time set 20ms
          and: content_checker set to a function that returns 0, 3, 0, 5, 0, 3

        When: User calls SerialConnectionGeneric.recv(100) 3 times.
         and: MockSerialConnection.recv set to return 2 bytes repeatedly.

        Then: SerialConnectionGeneric.recv calls MockSerialConnection.recv 6 times.
         and: SerialConnectionGeneric.recv returns only the first 3 bytes, then the next 5 bytes, then the next 3.
        """
        # Given
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

        uut = SerialConnectionGeneric(connection=self.mock,
                                      timeout=.100,
                                      message_separator_time=.020,
                                      content_checker=test_checker)

        # When
        self.mock.recv_return_queue = [b"12", b"34", b"56", b"78", b"9A", b"BC"]

        data = uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 2)
        self.assertEqual(data, b"123")

        data = uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 4)
        self.assertEqual(data, b"45678")

        data = uut.recv(max_bytes=100)
        self.assertEqual(len(self.mock.recv_max_bytes_lengths), 6)
        self.assertEqual(data, b"9AB")


if __name__ == '__main__':
    unittest.main()
