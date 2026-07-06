# diaggrok-provenance: re
"""Type definitions for diaggrok parsers."""
from typing import Any, Protocol


class ParserFunc(Protocol):
    """Signature every parser must satisfy."""
    def __call__(self, log_time: int, data: bytes) -> Any: ...
