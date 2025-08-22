# Server Logging
# ---------------------------------------------------------------------------------
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import click
import pyghidra
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    FunctionSearchResults,
    ImportInfos,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # Critical for STDIO transport
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[PyGhidraContext]:
    """Manage server startup and shutdown lifecycle."""
    try:
        yield server._pyghidra_context
    finally:
        # pyghidra_context.close()
        pass


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)


# MCP Tools
# ---------------------------------------------------------------------------------
@mcp.tool()
async def decompile_function(binary_name: str, name: str, ctx: Context) -> DecompiledFunction:
    """Decompiles a function in a specified binary and returns its pseudo-C code.

    Args:
        binary_name: The name of the binary containing the function.
        name: The name of the function to decompile.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.decompile_function(name)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error decompiling function: {e!s}")
        ) from e


@mcp.tool()
def search_functions_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> FunctionSearchResults:
    """Searches for functions within a binary by name.

    Args:
        binary_name: The name of the binary to search within.
        query: The substring to search for in function names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        functions = tools.search_functions_by_name(query, offset, limit)
        return FunctionSearchResults(functions=functions)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for functions: {e!s}")
        ) from e


@mcp.tool()
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """
    Search for symbols by case insensitive substring within a specific binary
    Symbols include Functions, Labels, Classes, Namespaces, Externals,
    Dynamics, Libraries, Global Variables, Parameters, and Local Variables

    Return: A paginatedlist of matches.

    Args:
        binary_name: The name of the binary to search within.
        query: The substring to search for in symbol names (case-insensitive).
        offset: The number of results to skip.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
def search_code(binary_name: str, query: str, ctx: Context, limit: int = 5) -> CodeSearchResults:
    """
    Perform a semantic code search over a binarys decompiled pseudo C output
    powered by a vector database for similarity matching.

    This returns the most relevant functions or code blocks whose semantics
    match the provided query even if the exact text differs. Results are
    Ghidra generated pseudo C enabling natural language like exploration of
    binary code structure.

    For best results provide a short distinctive query such as a function
    signature or key logic snippet to minimize irrelevant matches.

    Args:
        binary_name: Name of the binary to search within.
        query: Code snippet signature or description to match via semantic search.
        limit: Maximum number of top scoring results to return (default: 5).
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        results = tools.search_code(query, limit)
        return CodeSearchResults(results=results)
    except Exception as e:
        if isinstance(e, ValueError):
            raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error searching for code: {e!s}")
        ) from e


@mcp.tool()
def list_project_binaries(ctx: Context) -> list[str]:
    """Lists the names of all binaries currently loaded in the Ghidra project."""
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        return list(pyghidra_context.programs.keys())
    except Exception as e:
        raise McpError(
            ErrorData(code=INTERNAL_ERROR, message=f"Error listing project binaries: {e!s}")
        ) from e


@mcp.tool()
def list_project_program_info(ctx: Context) -> ProgramInfos:
    """
    Retrieve metadata and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished
    - metadata: Additional attributes or annotations provided by the analysis toolchain

    Use this to inspect the full set of binaries in the project, monitor analysis
    progress, or drive follow up actions such as listing imports/exports or running
    code searches on specific programs.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_infos = []
        for _name, pi in pyghidra_context.programs.items():
            program_infos.append(
                ProgramInfo(
                    name=pi.name,
                    file_path=str(pi.file_path) if pi.file_path else None,
                    load_time=pi.load_time,
                    analysis_complete=pi.analysis_complete,
                    metadata=pi.metadata,
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
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               export names. Use to limit irrelevant results and narrow
               context for analysis.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
        binary_name: Name of the binary to inspect.
        query: Strongly recommended. Regex pattern to match specific
               import names. Use to reduce irrelevant results and narrow
               context for downstream reasoning.
        offset: Number of matching results to skip (for pagination).
        limit: Maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
        binary_name: The name of the binary to search for cross-references in.
        name_or_address: The name of the function, symbol, or a specific address (e.g., '0x1004010')
        to find cross-references to.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
    limit: int = 25,
) -> StringSearchResults:
    """Searches for strings within a binary by name.
    This can be very useful to gain general understanding of behaviors.

    Args:
        binary_name: The name of the binary to search within.
        query: A query to filter strings by.
        limit: The maximum number of results to return.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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


def init_pyghidra_context(
    mcp: FastMCP, input_paths: list[Path], project_name: str, project_directory: str
) -> FastMCP:
    if not input_paths:
        raise ValueError("Missing Input Paths!")

    bin_paths = [Path(p) for p in input_paths]

    logger.info(f"Analyzing {', '.join(map(str, bin_paths))}")
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    pyghidra_context = PyGhidraContext(project_name, project_directory)
    logger.info(f"Importing binaries: {project_directory}")
    pyghidra_context.import_binaries(bin_paths)
    logger.info(f"Analyzing project: {pyghidra_context.project}")
    pyghidra_context.analyze_project()

    mcp._pyghidra_context = pyghidra_context
    logger.info("Server intialized")

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
@click.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse"]),
    default="stdio",
    envvar="MCP_TRANSPORT",
    help="Transport protocol to use: stdio, streamable-http, or sse (legacy)",
)
@click.option(
    "--project-name",
    default="pyghidra_mcp",
    help="Name of the Ghidra project.",
)
@click.option(
    "--project-directory",
    default="pyghidra_mcp_projects",
    type=click.Path(),
    help="Directory to store the Ghidra project.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1, required=True)
def main(
    transport: str, input_paths: list[Path], project_name: str, project_directory: str
) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp
    - transport: Supports stdio, streamable-http, and sse transports.
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on port 8000.

    """

    init_pyghidra_context(mcp, input_paths, project_name, project_directory)

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport == "streamable-http":
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Invalid transport: {transport}")
    finally:
        mcp._pyghidra_context.close()


if __name__ == "__main__":
    main()
