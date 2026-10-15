"""MCP Auth Bridge public embedding API."""

from ._version import __version__ as __version__
from .app import create_app
from .config import BridgeSettings
from .tokens import Principal

__all__ = ["BridgeSettings", "Principal", "create_app"]
