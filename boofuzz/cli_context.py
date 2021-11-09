import attr

from .sessions import Session


@attr.s
class CliContext(object):
    """Context for Click commands' Context.obj"""

    session = attr.ib(type=Session)
