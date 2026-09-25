"""Python SDK for Valet — agents hold handles, never secrets."""

from .client import ValetClient, ValetError

__all__ = ["ValetClient", "ValetError"]
__version__ = "0.1.0"
