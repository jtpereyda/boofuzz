# Sulley EXception Class


class BoofuzzError(Exception):
    pass


class BoofuzzRestartFailedError(BoofuzzError):
    pass


class SullyRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
