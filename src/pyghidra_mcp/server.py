# Server
# ---------------------------------------------------------------------------------
import hashlib
import json
import os
import sys
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import click
import pyghidra
from click_option_group import optgroup
from loguru import logger
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    BinaryMetadata,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    ImageBaseResult,
    ImportInfos,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

# Configure loguru to output to stderr (critical for STDIO transport)
# Use enqueue=True to prevent blocking in multi-threaded scenarios (e.g., with debuggers)
logger.remove()
logger.add(
    sys.stderr,
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<level>{message}</level>"
    ),
    level="INFO",
    enqueue=True,  # Async logging to prevent blocking on stderr writes
)


# Lazy Initialization
# ---------------------------------------------------------------------------------

# Global configuration for delayed context initialization
_context_config: dict[str, Any] = {}
_pyghidra_context: PyGhidraContext | None = None
_pyghidra_launcher: Any = None  # Launcher for JVM cleanup
_context_lock = threading.Lock()  # Protect context initialization from race conditions

# Track transport mode for JVM lifecycle management
_transport_mode: Literal["stdio", "sse", "streamable-http"] = "stdio"


def get_or_create_context() -> PyGhidraContext:
    """
    Get or create the PyGhidraContext instance (lazy initialization).

    This creates the context on first call, allowing multiple MCP server instances
    to start without immediately contending for Ghidra project locks.

    Thread-safe: Uses double-checked locking to prevent race conditions when
    multiple threads attempt to create the context simultaneously.
    """
    global _pyghidra_context

    # Fast path: no lock needed if context already exists
    if _pyghidra_context is not None:
        return _pyghidra_context

    # Slow path: acquire lock for creation
    with _context_lock:
        # Double-check: another thread might have created it while we waited
        if _pyghidra_context is not None:
            return _pyghidra_context

        if not _context_config:
            raise RuntimeError(
                "Context not initialized. Call init_pyghidra_context() first."
            )

        config = _context_config
        _pyghidra_context = PyGhidraContext(
            project_name=config["project_name"],
            project_path=config["project_directory"],
            force_analysis=config.get("force_analysis", False),
            verbose_analysis=config.get("verbose_analysis", False),
            no_symbols=config.get("no_symbols", False),
            gdts=config.get("gdts", []),
            program_options=config.get("program_options"),
            gzfs_path=config.get("gzfs_path"),
            threaded=config.get("threaded", True),
            max_workers=config.get("max_workers"),
            wait_for_analysis=config.get("wait_for_analysis", False),
        )

        logger.info(f"PyGhidraContext created: {_pyghidra_context.project_name}")
        return _pyghidra_context


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle.

    Context is created lazily on first tool call, not at server startup.

    CRITICAL: Following PyGhidra documentation pattern from first-script.md:95-98
    - Always call launcher.terminate() in finally block
    - Ensures JVM is properly shutdown even on errors
    - Prevents resource leaks (memory, file handles, threads)

    NOTE: JVM cleanup only happens in stdio mode. For SSE/streamable-http,
    the JVM lifecycle matches the HTTP server process lifecycle (via atexit).
    """
    try:
        yield None  # type: ignore
    finally:
        global _pyghidra_launcher, _pyghidra_context

        # Only close JVM in stdio mode (where lifespan = process lifecycle)
        # For SSE/streamable-http, JVM is managed by Starlette/atexit
        if _transport_mode == "stdio":
            if _pyghidra_launcher is not None:
                logger.info("Shutting down Ghidra JVM...")
                try:
                    import jpype
                    if jpype.isJVMStarted():
                        if hasattr(_pyghidra_launcher, 'stop'):
                            _pyghidra_launcher.stop()
                        # Shutdown JVM
                        jpype.shutdownJVM()
                        logger.info("Ghidra JVM terminated successfully")
                    _pyghidra_launcher = None
                except Exception as e:
                    logger.error(f"Error terminating Ghidra JVM: {e}")

            # Then close context
            if _pyghidra_context is not None:
                try:
                    _pyghidra_context.close()
                    logger.info("PyGhidra context closed")
                except Exception as e:
                    logger.error(f"Error closing context: {e}")
        else:
            # For SSE/streamable-http, log but don't cleanup
            logger.debug(f"Skipping JVM cleanup in lifespan (transport={_transport_mode})")


# JVM Cleanup for SSE/HTTP Transports
# ---------------------------------------------------------------------------------
async def cleanup_jvm_http() -> None:
    """Cleanup JVM for SSE/streamable-http transports."""
    global _pyghidra_launcher, _pyghidra_context

    logger.info("HTTP server shutting down, cleaning up JVM...")
    if _pyghidra_launcher is not None:
        try:
            import jpype
            if jpype.isJVMStarted():
                if hasattr(_pyghidra_launcher, 'stop'):
                    _pyghidra_launcher.stop()
                jpype.shutdownJVM()
                logger.info("Ghidra JVM terminated successfully")
            _pyghidra_launcher = None
        except Exception as e:
            logger.error(f"Error terminating Ghidra JVM: {e}")

    if _pyghidra_context is not None:
        try:
            _pyghidra_context.close()
            logger.info("PyGhidra context closed")
        except Exception as e:
            logger.error(f"Error closing context: {e}")


def cleanup_jvm_atexit() -> None:
    """Synchronous atexit handler for JVM cleanup."""
    logger.info("Process exiting, ensuring JVM cleanup...")
    # Run async cleanup in new event loop if needed
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(cleanup_jvm_http())
        loop.close()
    except Exception as e:
        logger.error(f"Error in atexit JVM cleanup: {e}")


# Register atexit handler for SSE/HTTP modes
import atexit


atexit.register(cleanup_jvm_atexit)


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


# MCP Tools
# ---------------------------------------------------------------------------------
@mcp.tool()
async def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompiles a function in the currently loaded program and returns its pseudo-C code.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary containing the function.
        name_or_address: The name or address of the function to decompile.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.decompile_function_by_name_or_addr(name_or_address)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error decompiling function: {e!s}")
        ) from e


@mcp.tool()
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Searches for symbols, including functions, within a binary by name.

    This tool searches for symbols by a case-insensitive substring. Symbols include
    Functions, Labels, Classes, Namespaces, Externals, Dynamics, Libraries,
    Global Variables, Parameters, and Local Variables.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to search within.
        query: The substring to search for in symbol names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        symbols = tools.search_symbols_by_name(query, offset, limit)
        return SymbolSearchResults(symbols=symbols)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for symbols: {e!s}")
        ) from e


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """
    Retrieve binary name, path, and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file on disk (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished

    Use this to inspect the full set of binaries in the project, monitor analysis
    progress, or drive follow up actions such as listing imports/exports or running
    code searches on specific programs.

    Args:
        ctx: The MCP request context (provided by FastMCP)
    """
    try:
        pyghidra_context = get_or_create_context()
        program_infos = []
        for _name, pi in pyghidra_context.programs.items():
            program_infos.append(
                ProgramInfo(
                    name=pi.name,
                    file_path=str(pi.file_path) if pi.file_path else None,
                    load_time=pi.load_time,
                    analysis_complete=pi.analysis_complete,  # Thread-safe property access
                    metadata={},
                )
            )
        return ProgramInfos(programs=program_infos)
    except Exception as e:
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error listing project program info: {e!s}",
            )
        ) from e


@mcp.tool()
def list_project_binary_metadata(binary_name: str, ctx: Context) -> BinaryMetadata:
    """
    Retrieve detailed metadata for a specific program (binary) in the active project.

    This tool provides extensive information about a binary, including its architecture,
    compiler, executable format, and various analysis metrics like the number of
    functions and symbols. It is useful for gaining a deep understanding of a
    binary's composition and properties. For example, you can use it to determine
    the processor (`Processor`), endianness (`Endian`), or check if it's a
    relocatable file (`Relocatable`). The results also include hashes like MD5/SHA256
    and details from the executable format (e.g., ELF or PE).

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to retrieve metadata for.

    Returns:
        An object containing detailed metadata for the specified program.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        metadata_dict = program_info.metadata
        return BinaryMetadata.model_validate(metadata_dict)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error retrieving binary metadata: {e!s}",
            )
        ) from e


@mcp.tool()
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Deletes a binary (program) from the project.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to delete.
    """
    try:
        pyghidra_context = get_or_create_context()
        if pyghidra_context.delete_program(binary_name):
            return f"Successfully deleted binary: {binary_name}"
        else:
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=f"Binary '{binary_name}' not found or could not be deleted.",
                )
            )
    except Exception as e:
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error deleting binary: {e!s}")
        ) from e


@mcp.tool()
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """
    Retrieve exported functions and symbols from a given binary,
    with optional regex filtering to focus on only the most relevant items.

    For large binaries, using the `query` parameter is strongly recommended
    to reduce noise and improve downstream reasoning. Specify a substring
    or regex to match export names. For example: `query="init"`
    to list only initialization-related exports.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               export names. Use to limit irrelevant results and narrow
               context for analysis.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        exports = tools.list_exports(query=query, offset=offset, limit=limit)
        return ExportInfos(exports=exports)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing exports: {e!s}")
        ) from e


@mcp.tool()
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """
    Retrieve imported functions and symbols from a given binary,
    with optional filtering to return only the most relevant matches.

    This tool is most effective when you use the `query` parameter to
    focus results — especially for large binaries — by specifying a
    substring or regex that matches the desired import names.
    For example: `query="socket"` to only see socket-related imports.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               import names. Use to reduce irrelevant results and narrow
               context for downstream reasoning.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        imports = tools.list_imports(query=query, offset=offset, limit=limit)
        return ImportInfos(imports=imports)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing imports: {e!s}")
        ) from e


@mcp.tool()
def list_cross_references(
    binary_name: str, name_or_address: str, ctx: Context
) -> CrossReferenceInfos:
    """Finds and lists all cross-references (x-refs) to a given function, symbol, or address within
    a binary. This is crucial for understanding how code and data are used and related.
    If an exact match for a function or symbol is not found,
    the error message will suggest other symbols that are close matches.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to search for cross-references in.
        name_or_address: The name of the function, symbol, or a specific address (e.g., '0x1004010')
        to find cross-references to.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        cross_references = tools.list_cross_references(name_or_address)
        return CrossReferenceInfos(cross_references=cross_references)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing cross-references: {e!s}")
        ) from e


@mcp.tool()
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Searches for strings within a binary by name.
    This can be very useful to gain general understanding of behaviors.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to search within.
        query: A query to filter strings by.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        strings = tools.search_strings(query=query, limit=limit)
        return StringSearchResults(strings=strings)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for strings: {e!s}")
        ) from e


@mcp.tool()
def get_image_base(binary_name: str, ctx: Context) -> ImageBaseResult:
    """Get the image base address of a binary.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to get the image base for.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        image_base = tools.get_image_base()
        return ImageBaseResult(image_base=image_base)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error getting image base: {e!s}")) from e


@mcp.tool()
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Reads raw bytes from memory at a specified address.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary to read bytes from.
        address: The memory address to read from (supports hex format with or without 0x prefix).
        size: The number of bytes to read (default: 32, max: 8192).
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.read_bytes(address=address, size=size)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error reading bytes: {e!s}")) from e


@mcp.tool()
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: CallGraphDirection = CallGraphDirection.CALLING,
    display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
) -> CallGraphResult:
    """Generates a mermaidjs function call graph for a specified function.

    Typically the 'calling' callgraph is most useful.
    The resulting graph string is mermaidjs format. This output is critical for correct rendering.
    The graph details function calls originating from (calling) or terminating at (called)
    the target function.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_name: The name of the binary containing the function.
        function_name: The name of the function to generate the call graph for.
        direction: Direction of the call graph (calling or called).
        display_type: Format of the graph (flow, flow_ends).
        condense_threshold: Maximum number of edges before graph condensation is triggered.
        top_layers: Number of top layers to show in a condensed graph.
        bottom_layers: Number of bottom layers to show in a condensed graph.
    """
    try:
        pyghidra_context = get_or_create_context()
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.gen_callgraph(
            function_name_or_address=function_name,
            cg_direction=direction,
            cg_display_type=display_type,
            include_refs=True,
            max_depth=None,
            max_run_time=60,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error generating call graph: {e!s}")
        ) from e


@mcp.tool()
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        ctx: The MCP request context (provided by FastMCP)
        binary_path: The path to the binary file to import.
    """
    try:
        # Import binary in background mode with progress reporting via logging
        # (MCP progress context updates not yet widely supported by clients)
        pyghidra_context = get_or_create_context()
        pyghidra_context.import_binary_backgrounded(binary_path)
        return (
            f"Importing {binary_path} in the background."
            "When ready, it will appear analyzed in binary list."
        )
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error importing binary: {e!s}")
        ) from e


def init_pyghidra_context(
    mcp: FastMCP,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdts: list[str],
    program_options_path: str | None,
    gzfs_path: str | None,
    threaded: bool,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    transport: str = "stdio",
) -> FastMCP:
    """
    Lightweight initialization that stores configuration without creating a Ghidra project.

    The actual Ghidra project is created lazily on the first tool call via get_or_create_context().
    This allows multiple MCP server instances to start without lock contention.
    """
    global _context_config, _transport_mode

    # Store transport mode for JVM lifecycle management
    _transport_mode = transport

    logger.info("Server initializing (lazy mode - project created on first tool call)...")

    program_options: dict | None = None
    if program_options_path:
        with open(program_options_path) as f:
            program_options = json.load(f)

    # Store configuration for lazy initialization
    _context_config = {
        "project_name": project_name,
        "project_directory": project_directory,
        "force_analysis": force_analysis,
        "verbose_analysis": verbose_analysis,
        "no_symbols": no_symbols,
        "gdts": gdts,
        "program_options": program_options,
        "gzfs_path": gzfs_path,
        "threaded": threaded,
        "max_workers": max_workers,
        "wait_for_analysis": wait_for_analysis,
    }

    # Only initialize pyghidra itself, don't create a project yet
    # Redirect stdout to stderr at the OS level to prevent Java/pyghidra output from breaking MCP stdio protocol
    stdout_fd = sys.stdout.fileno()
    stderr_fd = sys.stderr.fileno()

    # Save original stdout fd
    original_stdout_fd = os.dup(stdout_fd)

    global _pyghidra_launcher

    try:
        # Redirect stdout to stderr
        os.dup2(stderr_fd, stdout_fd)

        # CRITICAL: Capture launcher reference for cleanup
        # Following PyGhidra documentation pattern: launcher = api.start()
        _pyghidra_launcher = pyghidra.start(False)  # Disable verbose output
        logger.info("Ghidra JVM started successfully")
    except Exception as e:
        raise
    finally:
        # Always restore original stdout and close the duplicated fd
        # Use a nested try/except to ensure we close the fd even if dup2 fails
        try:
            os.dup2(original_stdout_fd, stdout_fd)
        finally:
            os.close(original_stdout_fd)

    # Note: input_paths are ignored in server mode - use import_binary tool instead
    if input_paths:
        logger.info(
            f"Note: input_paths provided ({len(input_paths)} files) "
            "but will not be imported automatically. "
            "Use the import_binary tool instead."
        )

    # These flags require immediate project access, which doesn't fit lazy mode
    if list_project_binaries or delete_project_binary:
        logger.warning(
            "--list-project-binaries and --delete-project-binary require "
            "immediate project access, which is not supported in lazy mode. "
            "Please start the server and use the tools instead."
        )
        if list_project_binaries:
            click.echo(
                "List binaries feature not available in lazy mode. "
                "Start server and use tools."
            )
        if delete_project_binary:
            click.echo(
                "Delete binary feature not available in lazy mode. "
                "Start server and use tools."
            )
        sys.exit(1)

    logger.info("Server ready - Ghidra project will be created on first tool call")
    return mcp


# MCP Server Entry Point
# ---------------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    __version__,
    "-v",
    "--version",
    help="Show version and exit.",
)
# --- Server Options ---
@optgroup.group("Server Options")
@optgroup.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse", "http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    show_default=True,
    help="Transport protocol to use.",
)
@optgroup.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    show_default=True,
    help="Port to listen on for HTTP-based transports.",
)
@optgroup.option(
    "-o",
    "--host",
    type=str,
    default="127.0.0.1",
    envvar="MCP_HOST",
    show_default=True,
    help="Host to listen on for HTTP-based transports.",
)
@optgroup.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("pyghidra_mcp_projects/pyghidra_mcp"),
    show_default=True,
    help="Path to the Ghidra project.",
)
@optgroup.option(
    "--threaded/--no-threaded",
    default=True,
    show_default=True,
    help="Allow threaded analysis. Disable for debug.",
)
@optgroup.option(
    "--max-workers",
    type=int,
    default=0,  # 0 means multiprocessing.cpu_count()
    show_default=True,
    help="Number of workers for threaded analysis. Defaults to CPU count.",
)
@optgroup.option(
    "--wait-for-analysis/--no-wait-for-analysis",
    default=False,
    show_default=True,
    help="Wait for initial project analysis to complete before starting the server.",
)
# --- Project Options ---
@optgroup.group("Project Management")
@optgroup.option(
    "--list-project-binaries",
    is_flag=True,
    help="List all ingested binaries in the project.",
)
@optgroup.option(
    "--delete-project-binary",
    type=str,
    help="Delete a specific binary (program) from the project by name.",
)
# --- Analysis Options ---
@optgroup.group("Analysis Options")
@optgroup.option(
    "--force-analysis/--no-force-analysis",
    default=False,
    show_default=True,
    help="Force a new binary analysis each run.",
)
@optgroup.option(
    "--verbose-analysis/--no-verbose-analysis",
    default=False,
    show_default=True,
    help="Verbose logging for analysis step.",
)
@optgroup.option(
    "--no-symbols/--with-symbols",
    default=False,
    show_default=True,
    help="Turn off symbols for analysis.",
)
@optgroup.option(
    "--gdt",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to GDT files (can be specified multiple times).",
)
@optgroup.option(
    "--program-options",
    type=click.Path(exists=True),
    help="Path to a JSON file containing program options.",
)
@optgroup.option(
    "--gzfs-path",
    type=click.Path(),
    help="Location to store GZFs of analyzed binaries.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    input_paths: list[Path],
    project_path: Path,
    port: int,
    host: str,
    threaded: bool,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdt: tuple[str, ...],
    program_options: str | None,
    gzfs_path: str | None,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp\n
    - transport: Supports stdio, streamable-http, and sse transports.\n
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on the specified port (default 8000).

    """
    # Generate unique project name to avoid lock conflicts when multiple agents run concurrently
    if input_paths:
        # Use hash of first input file for project name
        first_bin_hash = hashlib.sha256(str(input_paths[0]).encode()).hexdigest()[:12]
        project_name = f"{project_path.stem}_{first_bin_hash}"
    else:
        # Fallback to process ID + timestamp if no input paths provided
        project_name = f"{project_path.stem}_{os.getpid()}_{int(time.time())}"

    project_directory = str(project_path.parent)
    mcp.settings.port = port
    mcp.settings.host = host

    init_pyghidra_context(
        mcp=mcp,
        input_paths=input_paths,
        project_name=project_name,
        project_directory=project_directory,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=list(gdt),
        program_options_path=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        list_project_binaries=list_project_binaries,
        delete_project_binary=delete_project_binary,
        transport=transport,
    )

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport in ["streamable-http", "http"]:
        mcp.run(transport="streamable-http")
    elif transport == "sse":
        mcp.run(transport="sse")
    else:
        raise ValueError(f"Invalid transport: {transport}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Unknown error occured: {e}")
