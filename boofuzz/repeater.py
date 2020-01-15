from abc import ABC, abstractmethod
import time


class Repeater(ABC):
    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def repeat(self):
        pass

    @abstractmethod
    def reset(self):
        pass


class TimeRepeater(Repeater):
    def __init__(self, time):
        self.time = time
        self._starttime = None

    def start(self):
        self._starttime = time.time()

    def repeat(self):
        return time.time() - self._starttime < self.time

    def reset(self):
        self._starttime = None


class CountRepeater(Repeater):
    def __init__(self, count):
        self.count = count
        self._reps = 0

    def start(self):
        return

    def repeat(self):
        self._reps += 1
        return self._reps <= self.count

    def reset(self):
        self._reps = 0
