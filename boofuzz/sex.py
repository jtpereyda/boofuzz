import attr
# Sulley EXception Class


class BoofuzzError(Exception):
    pass


class BoofuzzRestartFailedError(BoofuzzError):
    pass


class BoofuzzTargetConnectionFailedError(BoofuzzError):
    pass


class BoofuzzTargetConnectionReset(BoofuzzError):
    pass


@attr.s
class BoofuzzTargetConnectionAborted(BoofuzzError):
    """
    Raised on `errno.ECONNABORTED`.
    """
    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class SullyRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
