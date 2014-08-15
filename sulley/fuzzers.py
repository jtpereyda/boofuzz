class Fuzzer(object):
    blocks = []

    def __init__(self):
        pass

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
