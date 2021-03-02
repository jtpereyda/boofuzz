# Import blocks at this level for backwards compatibility.
# blocks/ used to be blocks.py
from .aligned import Aligned
from .block import Block
from .checksum import Checksum
from .repeat import Repeat
from .request import Request
from .size import Size

__all__ = ["Block", "Checksum", "Repeat", "Request", "Size", "REQUESTS", "Aligned"]

REQUESTS = {}
CURRENT = None
