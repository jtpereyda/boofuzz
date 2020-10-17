import attr


@attr.s
class BoofuzzFailure(Exception):
    """Raises a failure in the current test case.

    This is most important when failures in the target may not be noticed until the next test case. In such a situation,
    it may be necessary to abort the test case before a fuzz message is even sent, as the fuzz message may be poorly
    defined outside the context of a valid partial protocol exchange.
    """

    message = attr.ib(type=str, default="")
    pass


class BoofuzzError(Exception):
    pass


class BoofuzzRestartFailedError(BoofuzzError):
    pass


class BoofuzzTargetConnectionFailedError(BoofuzzError):
    pass


class BoofuzzOutOfAvailableSockets(BoofuzzError):
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


class BoofuzzNoSuchTestCase(BoofuzzError):
    pass


class BoofuzzRpcError(BoofuzzError):
    pass


class SullyRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass


class BoofuzzSSLError(BoofuzzError):
    pass


class BoofuzzNameResolutionError(BoofuzzError):
    pass
