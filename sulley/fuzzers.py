from .sex import MustImplementException


class Fuzzer(object):
    blocks = []

    def __init__(self):
        pass

    def send(self):
        raise MustImplementException("You must implement a send() function in your fuzzer!")

    def __repr__(self):
        return "<Fuzzer>"


class BlockBasedFuzzer(Fuzzer):
    def __init__(self):
        super(BlockBasedFuzzer, self).__init__()

    def __repr__(self):
        return "<BlockBasedFuzzer>"


class DumbFileFuzzer(Fuzzer):
    def __init__(self):
        super(DumbFileFuzzer, self).__init__()

    def __repr__(self):
        return "<FileFuzzer>"
