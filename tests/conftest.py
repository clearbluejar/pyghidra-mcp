import os
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    import gpu_adrp_scanner  # noqa: F401
except ImportError:
    _env_sg = os.environ.get("SUPERGHIDRA_PATH")
    if _env_sg and os.path.exists(_env_sg):
        if _env_sg not in sys.path:
            sys.path.insert(0, _env_sg)
    else:
        _SUPERGHIDRA = r"E:\02_Projects\SuperGhidra"
        if os.path.exists(_SUPERGHIDRA) and _SUPERGHIDRA not in sys.path:
            sys.path.insert(0, _SUPERGHIDRA)
