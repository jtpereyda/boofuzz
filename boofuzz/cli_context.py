import attr

from .sessions import Session


@attr.s
class CliContext:
    """Context for Click commands' Context.obj"""

    session = attr.ib(type=Session)
