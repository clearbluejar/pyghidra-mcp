# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**PyGhidra-MCP** is a command-line Model Context Protocol (MCP) server that exposes Ghidra's reverse engineering capabilities to AI agents and LLM-based tooling. It bridges Ghidra's ProgramAPI and FlatProgramAPI to Python via `pyghidra` and `jpype`, then exposes functionality through the MCP standard.

**Key Features:**
- CLI-first operation (no GUI required)
- Lazy initialization - Ghidra context created on first tool call, not server startup
- Designed for automation and CI/CD integration
- Concurrent binary analysis with ThreadPoolExecutor
- Multiple transport protocols (stdio, HTTP/streamable-http, SSE)
- Project-wide analysis with temporary project management

## Commands

### Development Setup
```bash
# Install dependencies
make dev-setup          # uv sync --extra dev + pre-commit hooks

# Or manually:
uv sync                 # install dependencies
uv sync --extra dev     # with dev dependencies
uv run pre-commit install
```

### Running the Server
```bash
# Run the MCP server (stdio transport by default)
make run                # uv run pyghidra-mcp

# Or with specific options:
pyghidra-mcp -t stdio --project-path /path/to/project

# HTTP-based transports:
pyghidra-mcp -t streamable-http -p 8000
pyghidra-mcp -t sse -p 8000
```

### Testing and Quality
```bash
make test               # Full test suite (unit + integration)
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make lint               # Ruff code style check
make format             # Ruff format + fix
make typecheck          # Ruff type checking (pyright)
make check              # All quality checks (lint + typecheck + test)
make dev                # Format + check
make clean              # Clean build artifacts
make build              # Build distribution packages
```

### Environment Configuration

Required environment variable:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # e.g., /path/to/ghidra_12.0_PUBLIC
```

Optional (JAVA_HOME inferred from Ghidra if not set):
```bash
export JAVA_HOME=/path/to/java
```

## Architecture

### Core Components

**PyGhidraContext** (`context.py`)
- Manages Ghidra project lifecycle (creation, program imports, cleanup)
- Handles temporary project creation/deletion (temp_mode)
- Manages program loading and analysis with ThreadPoolExecutor
- Implements lazy initialization pattern for startup efficiency
- Stale lock file recovery (handles crashes with automatic cleanup)

**GhidraTools** (`tools.py`)
- All MCP tool implementations
- Function decompilation with timeout support
- Symbol/function lookup with "Did you mean..." suggestions
- Cross-reference analysis
- Call graph generation (via ghidrecomp)
- Import/export listing with regex filtering
- String search with direct filtering (instant, no indexing required)
- Raw memory read operations

**MCP Server** (`server.py`)
- FastMCP-based server implementation
- Lazy initialization: context created on first tool call, not startup
- Supports stdio, streamable-http, and SSE transports
- Tool registration with `@mcp.tool()` decorator
- Error handling with MCP ErrorData (INTERNAL_ERROR, INVALID_PARAMS)
- Automatic cleanup via atexit handler

**Models** (`models.py`)
- Pydantic data models for type-safe MCP interactions
- Request/response models for all tools
- Enums for CallGraphDirection and CallGraphDisplayType

### Important Patterns

**Lazy Initialization**
- `init_pyghidra_context()` stores configuration in global `_context_config`
- `get_or_create_context()` creates PyGhidraContext on first tool call
- Allows multiple server instances to start without Ghidra lock contention
- Temporary project directory created with unique name (PID + timestamp)

**Temporary Project Management**
- Projects created in `pyghidra_mcp_projects/mcp_{pid}_{timestamp}/`
- `temp_mode=True` flags project for cleanup on close
- Cleanup handled by `cleanup_temp_project()` and atexit handler
- Stale lock recovery with `_MAX_LOCK_RETRIES = 1`

**Transport Protocols**
- `stdio`: Default for local CLI, reads stdin/writes stdout
- `streamable-http`: RESTful JSON RPC over HTTP (127.0.0.1:8000/mcp)
- `sse`: Legacy Server-Sent Events (127.0.0.1:8000/sse)

**Thread Pool Pattern**
- Background analysis with `ThreadPoolExecutor(max_workers=cpu_count)`
- Separate `import_executor` for binary imports (single worker)
- Shutdown sequence: import_executor → executor → programs → project

**Symbol/Function Resolution**
- `find_function()` and `find_symbol()` resolve by name or address
- Ambiguous matches raise with suggestions
- No matches raise with "Did you mean..." partial matches

### Code Quality Standards

- **Line length**: 100 characters (ruff)
- **Complexity**: McCabe max 10
- **Type checking**: Pyright with `reportMissingModuleSource = false` (for Java/JPype)
- **Pre-commit hooks**: ruff, ruff-format, pyright, pytest
- **Known ruff ignores**: `F821`, `E402` (due to Java/Python import issues)

### Testing Strategy

- **Unit tests**: `tests/unit/` (currently empty, uses doctest)
- **Integration tests**: `tests/integration/` with stdio/streamable-http clients
- **Concurrent testing**: `test_concurrent_streamable_client.py` tests multiple simultaneous tool calls

### Known Limitations

1. Requires Ghidra installation (GHIDRA_INSTALL_DIR must be set)
2. Java dependency through JPype (JAVA_HOME or inferred from Ghidra)
3. Threaded analysis has resource considerations (max_workers defaults to CPU count)
4. Temporary projects may persist on Windows due to file locking delays

### MCP Tools Reference

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile function to pseudo-C |
| `search_symbols_by_name` | Search symbols by substring |
| `list_project_binaries` | List all binaries with analysis status |
| `list_project_binary_metadata` | Get detailed binary metadata |
| `delete_project_binary` | Remove binary from project |
| `list_exports` | List exported functions (regex filter) |
| `list_imports` | List imported functions (regex filter) |
| `list_cross_references` | Find x-refs to function/address |
| `search_strings` | Search strings by filtering (instant, no indexing required) |
| `read_bytes` | Read raw memory bytes |
| `gen_callgraph` | Generate MermaidJS call graph |
| `import_binary` | Import binary into project |

### Adding New Tools

1. Add function to `GhidraTools` class in `tools.py`
2. Create Pydantic models in `models.py` if needed
3. Register with `@mcp.tool()` decorator in `server.py`
4. Call `get_or_create_context()` for context access
5. Add integration test in `tests/integration/`
6. Run `make test && make format` before committing
