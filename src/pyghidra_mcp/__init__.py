from . import server

__version__ = '0.1.0'
__author__ = 'clearbluejar'


def main() -> None:
    """Main entry point for the package."""
    server.main()


# Optionally expose other important items at package level
__all__ = ["main", "server"]
