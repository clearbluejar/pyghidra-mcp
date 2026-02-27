# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pyghidra-mcp is a Python MCP (Model Context Protocol) server that bridges Ghidra's reverse engineering capabilities with LLMs and AI agents. It enables headless binary analysis with concurrent processing, semantic code search via ChromaDB, and agent-driven automation.

## Common Commands

All commands use `uv` as the package manager.

```bash
# Setup
make dev-setup              # Install deps + pre-commit hooks
make install-dev            # Install dev dependencies only

# Running
make run                    # Start MCP server (stdio mode)
pyghidra-mcp -t streamable-http --wait-for-analysis /bin/ls  # HTTP mode

# Testing
make test                   # Full suite (unit + integration)
make test-unit              # Unit tests only
make test-integration       # Integration tests only
uv run pytest tests/integration/test_decompile_function.py -v          # Single file
uv run pytest tests/integration/test_search_code.py::test_search_code -v  # Single test

# Code quality
make lint                   # ruff check
make format                 # ruff format + fix
make check                  # lint + typecheck + test
make dev                    # format + check
```

Integration tests require a Ghidra installation (`GHIDRA_INSTALL_DIR` env var or `/ghidra` directory).

## Architecture

The server package lives in `src/pyghidra_mcp/` with a clear layered design:

- **server.py** — CLI entry point (Click), FastMCP server setup, transport configuration (stdio/streamable-http/sse), tool registration, lifespan management
- **mcp_tools.py** — Async MCP tool handlers that wrap `GhidraTools` methods. Uses `@mcp_error_handler` decorator for centralized error handling (ValueError → INVALID_PARAMS, others → INTERNAL_ERROR)
- **tools.py** — Core Ghidra analysis logic (`GhidraTools` class): decompilation, symbol/import/export listing, cross-references, call graphs, byte/string search. Uses `@handle_exceptions` decorator. Interacts with Ghidra via JPype/pyghidra
- **context.py** — `PyGhidraContext` manages Ghidra project lifecycle: project creation, binary import/analysis, ChromaDB collections for semantic search, thread pool for concurrent analysis. Contains `ProgramInfo` dataclass tracking per-binary state
- **models.py** — Pydantic models for all MCP tool responses (DecompiledFunction, ProgramInfo, ExportInfo, etc.)

A separate CLI client package lives in `cli/` (`pyghidra-mcp-cli`) for HTTP-based interaction.

## Key Patterns

- **Import ordering**: `F821` and `E402` ruff rules are ignored due to JPype/Java interop requiring specific import sequencing
- **Logging**: Always to stderr (critical for STDIO transport safety)
- **TYPE_CHECKING guards**: Ghidra types (`ghidra.*`) are imported only under `TYPE_CHECKING` since they require the JVM runtime
- **Function lookup**: Tools accept function name, partial name, or hex address strings
- **Ruff config**: line-length=100, target Python 3.10, rules: E/F/B/I/UP/N/W/C90/RUF

## Testing

- **Unit tests** (`tests/unit/`): Model validation, version checks — no Ghidra required
- **Integration tests** (`tests/integration/`): Full MCP client-server tests using compiled C test binaries. `conftest.py` provides fixtures for test binaries (compiled via gcc), server params, and Ghidra env detection
- Pre-commit hooks run ruff, pyright (on `src/` only), unit tests, and one integration test (`test_concurrent_streamable_client.py`)
