import time
from abc import ABCMeta, abstractmethod

from six import with_metaclass


class Repeater(with_metaclass(ABCMeta, object)):
    """Base Repeater class.

    :param sleep_time: Time to sleep between repetitions.
    :type sleep_time: float
    """

    def __init__(self, sleep_time):
        self.sleep_time = sleep_time

    @abstractmethod
    def start(self):
        """ Starts the repeater. """
        pass

    @abstractmethod
    def repeat(self):
        """Decides whether the operation should repeat.

        :return: True if the operation should repeat, False otherwise.
        :rtype: Bool
        """
        time.sleep(self.sleep_time)

    @abstractmethod
    def reset(self):
        """ Resets the internal state of the repeater. """
        pass

    @abstractmethod
    def log_message(self):
        """ Formats a message to output in a log file. It should contain info about your repetition."""
        pass


class TimeRepeater(Repeater):
    """Time-based repeater class. Starts a timer, and repeats until `duration` seconds have passed.

    :raises ValueError: Raised if a time <= 0 is specified.

    :param duration: The duration of the repitition.
    :type duration: float
    :param sleep_time: Time to sleep between repetitions.
    :type sleep_time: float
    """

    def __init__(self, duration, sleep_time=0):
        super(TimeRepeater, self).__init__(sleep_time)

        if duration <= 0:
            raise ValueError("Time must be a non-negative non-zero value")

        self.duration = duration
        self._starttime = None

    def start(self):
        """ Starts the timer. """
        self._starttime = time.time()

    def repeat(self):
        super(TimeRepeater, self).repeat()
        return time.time() - self._starttime < self.duration

    def reset(self):
        """ Resets the timer. """
        self._starttime = None

    def log_message(self):
        return "repeat for {}s".format(self.duration)


class CountRepeater(Repeater):
    """Count-Based repeater class. Repeats a fixed number of times.

    :raises ValueError: Raised if a count < 1 is specified.

    :param count: Total amount of packets to be sent. **Important**: Do not
                  confuse this parameter with the amount of repetitions.
                  Specifying 1 would send exactly one packet.
    :type count: int
    :param sleep_time: Time to sleep between repetitions.
    :type sleep_time: float
    """

    def __init__(self, count, sleep_time=0):
        super(CountRepeater, self).__init__(sleep_time)

        if count < 1:
            raise ValueError("Count must be greater or equal to 1")

        self.count = count
        self._reps = 0

    def start(self):
        return

    def repeat(self):
        super(CountRepeater, self).repeat()
        self._reps += 1
        return self._reps <= self.count

    def reset(self):
        self._reps = 0

    def log_message(self):
        return "repeat {} times".format(self.count)
