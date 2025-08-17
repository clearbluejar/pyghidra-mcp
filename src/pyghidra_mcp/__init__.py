from . import server
from .context import PyGhidraContext
from .tools import GhidraTools

__version__ = "0.1.7"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    server.main()


# Optionally expose other important items at package level
__all__ = ["GhidraTools", "PyGhidraContext", "main", "server"]
