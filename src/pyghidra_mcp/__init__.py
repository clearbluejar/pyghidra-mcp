from . import server

__version__ = "0.1.7"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    server.main()


from .context import PyGhidraContext
from .tools import GhidraTools

# Optionally expose other important items at package level
__all__ = ["GhidraTools", "PyGhidraContext", "main", "server"]
