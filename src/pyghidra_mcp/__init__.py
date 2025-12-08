from . import server
from .context import ProgramInfo, PyGhidraContext
from .tools import GhidraTools

__version__ = "0.1.12"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    server.main()


# Optionally expose other important items at package level
__all__ = ["GhidraTools", "ProgramInfo", "PyGhidraContext", "main", "server"]
