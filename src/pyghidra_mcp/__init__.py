__version__ = "0.2.7"
__author__ = "clearbluejar"


def main() -> None:
    """Main entry point for the package."""
    from .server import main as _main

    _main()


def __getattr__(name: str):
    """Lazy-load heavy modules to avoid pulling in chromadb/pyghidra at import time."""
    if name == "server":
        import importlib
        import sys

        fullname = f"{__name__}.server"
        if fullname in sys.modules:
            mod = sys.modules[fullname]
            setattr(sys.modules[__name__], name, mod)
            return mod
        mod = importlib.import_module(fullname)
        setattr(sys.modules[__name__], name, mod)
        return mod
    if name == "PyGhidraContext" or name == "ProgramInfo":
        from .context import ProgramInfo, PyGhidraContext

        if name == "PyGhidraContext":
            return PyGhidraContext
        return ProgramInfo
    if name == "GhidraTools":
        from .tools import GhidraTools

        return GhidraTools
    if name == "L2SQLiteCache":
        from .l2_cache import L2SQLiteCache

        return L2SQLiteCache
    if name == "DecompilerPool":
        from .decompiler_pool import DecompilerPool

        return DecompilerPool
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "DecompilerPool",
    "GhidraTools",
    "L2SQLiteCache",
    "ProgramInfo",
    "PyGhidraContext",
    "main",
    "server",
]
