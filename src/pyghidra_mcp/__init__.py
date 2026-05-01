__version__ = "0.2.2"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    from .server import main as _main

    _main()


def __getattr__(name: str):
    """Lazy-load heavy modules to avoid pulling in chromadb/pyghidra at import time."""
    if name == "server":
        from . import server

        return server
    if name == "PyGhidraContext" or name == "ProgramInfo":
        from .context import ProgramInfo, PyGhidraContext

        if name == "PyGhidraContext":
            return PyGhidraContext
        return ProgramInfo
    if name == "GhidraTools":
        from .tools import GhidraTools

        return GhidraTools
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["GhidraTools", "ProgramInfo", "PyGhidraContext", "main", "server"]
