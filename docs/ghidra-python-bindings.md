# Ghidra Python Bindings

Three layers enable Python-to-Ghidra interop in this project.

## 1. pyghidra (runtime bridge)

- **Production dependency**: `pyghidra>=2.2.1`
- Started in `server.py` with `pyghidra.start(False)` — initializes the JVM
- Primary bridge making Ghidra's Java API accessible from Python

## 2. JPype (low-level Java interop)

- pyghidra is built on top of JPype
- Used directly in `tools.py` (`JByte` for byte array handling in `read_bytes()`)
- Used implicitly for `java.io.File`, `java.lang.Enum`, `java.util.List` imports in `context.py`

## 3. ghidra-stubs (type stubs, dev-only)

- **Dev dependency only**: `ghidra-stubs>=11.3.2`
- Also installed in `.github/workflows/lint.yml` for CI type checking
- Provides Python type hints for `ghidra.*` Java classes so Pyright can do static analysis
- **Not used at runtime** — purely for IDE autocompletion and type checking

## Import Strategy

The codebase uses a two-tier pattern:

- **`TYPE_CHECKING` guards** at module level (`tools.py`, `context.py`) — import `ghidra.*` types for annotations only
- **Runtime imports inside functions** — lazy-load Ghidra classes only when the JVM is already running

This avoids import failures if the JVM isn't initialized and allows version-specific fallbacks (e.g., `DefinedStringIterator` → `DefinedDataIterator` for Ghidra 11.3.2 compat).

The ruff `F821` and `E402` ignores in `pyproject.toml` exist specifically to accommodate this import pattern.
