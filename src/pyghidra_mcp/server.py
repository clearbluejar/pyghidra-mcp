# Server
# ---------------------------------------------------------------------------------
import json
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
    BinaryMetadata,
    BytesReadResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
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
        yield server._pyghidra_context  # type: ignore
    finally:
        # pyghidra_context.close()
        pass


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


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
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Searches for symbols, including functions, within a binary by name.

    This tool searches for symbols by a case-insensitive substring. Symbols include
    Functions, Labels, Classes, Namespaces, Externals, Dynamics, Libraries,
    Global Variables, Parameters, and Local Variables.

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
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """
    Retrieve binary name, path, and analysis status for every program (binary) currently
    loaded in the active project.

    Returns a structured list of program entries, each containing:
    - name: The display name of the program
    - file_path: Absolute path to the binary file (if available)
    - load_time: Timestamp when the program was loaded into the project
    - analysis_complete: Boolean indicating if automated analysis has finished

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
                    metadata={},
                    code_collection=pi.code_collection is not None,
                    strings_collection=pi.strings_collection is not None,
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
        binary_name: The name of the binary to retrieve metadata for.

    Returns:
        An object containing detailed metadata for the specified binary.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
        binary_name: The name of the binary to delete.
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
    limit: int = 100,
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


@mcp.tool()
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Reads raw bytes from memory at a specified address.

    Args:
        binary_name: The name of the binary to read bytes from.
        address: The memory address to read from (supports hex format with or without 0x prefix).
        size: The number of bytes to read (default: 32, max: 8192).
    """
    try:
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
        program_info = pyghidra_context.get_program_info(binary_name)
        tools = GhidraTools(program_info)
        return tools.read_bytes(address=address, size=size)
    except ValueError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(e))) from e
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error reading bytes: {e!s}")) from e


@mcp.tool()
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        binary_path: The path to the binary file to import.
    """
    try:
        # We would like to do context progress updates, but until that is more
        # widely supported by clients, we will resort to this
        pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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
) -> FastMCP:
    bin_paths: list[str | Path] = [Path(p) for p in input_paths]
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    program_options: dict | None = None
    if program_options_path:
        with open(program_options_path) as f:
            program_options = json.load(f)

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    pyghidra_context = PyGhidraContext(
        project_name=project_name,
        project_path=project_directory,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=gdts,
        program_options=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
    )

    if list_project_binaries:
        binaries = pyghidra_context.list_binaries()
        if binaries:
            click.echo("Ghidra Project Binaries:")
            for binary_name in binaries:
                click.echo(f"- {binary_name}")
        else:
            click.echo("No binaries found in the project.")
        sys.exit(0)

    if delete_project_binary:
        try:
            if pyghidra_context.delete_program(delete_project_binary):
                click.echo(f"Successfully deleted binary: {delete_project_binary}")
            else:
                click.echo(f"Failed to delete binary: {delete_project_binary}", err=True)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
        sys.exit(0)

    if len(bin_paths) > 0:
        logger.info(f"Adding new bins: {', '.join(map(str, bin_paths))}")
        logger.info(f"Importing binaries to {project_directory}")
        pyghidra_context.import_binaries(bin_paths)

    logger.info(f"Analyzing project: {pyghidra_context.project}")
    pyghidra_context.analyze_project()

    if len(pyghidra_context.list_binaries()) == 0:
        logger.warning("No binaries were imported and none exist in the project.")

    mcp._pyghidra_context = pyghidra_context  # type: ignore
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
    type=click.Choice(["stdio", "streamable-http", "sse", "http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    help="Transport protocol to use: stdio, streamable-http (aka http), or sse (legacy)",
)
@click.option(
    "--project-path",
    type=click.Path(),
    default=Path("pyghidra_mcp_projects/pyghidra_mcp"),
    help="Location on disk which points to the Ghidra project to use. Can be an existing file.",
)
@click.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    help="Port to listen on for HTTP-based transports (streamable-http, sse).",
)
@click.option(
    "-o",
    "--host",
    type=str,
    default="127.0.0.1",
    envvar="MCP_HOST",
    help="Host to listen on for HTTP-based transports (streamable-http, sse).",
)
@click.option(
    "--threaded/--no-threaded",
    default=True,
    show_default=True,
    help="Allow threaded analysis. Disable for debug.",
)
@click.option(
    "--force-analysis/--no-force-analysis",
    default=False,
    help="Force a new binary analysis each run.",
)
@click.option(
    "--verbose-analysis/--no-verbose-analysis",
    default=False,
    help="Verbose logging for analysis step.",
)
@click.option(
    "--no-symbols/--with-symbols",
    default=False,
    help="Turn off symbols for analysis.",
)
@click.option(
    "--gdt",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to a GDT file for analysis. Can be specified multiple times.",
)
@click.option(
    "--program-options",
    type=click.Path(exists=True),
    help="Path to a JSON file containing program options (custom analyzer settings).",
)
@click.option(
    "--gzfs-path",
    type=click.Path(),
    help="Location to store GZFs of analyzed binaries.",
)
@click.option(
    "--max-workers",
    type=int,
    default=0,  # 0 means multiprocessing.cpu_count()
    help="Number of workers for threaded analysis. Defaults to CPU count.",
)
@click.option(
    "--wait-for-analysis/--no-wait-for-analysis",
    default=False,
    help="Wait for initial project analysis to complete before starting the server.",
)
@click.option(
    "--list-project-binaries",
    is_flag=True,
    help="List all ingested binaries in the project.",
)
@click.option(
    "--delete-project-binary",
    type=str,
    help="Delete a specific binary (program) from the project by name.",
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
    project_name = project_path.stem
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
    )

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport in ["streamable-http", "http"]:
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Invalid transport: {transport}")
    finally:
        mcp._pyghidra_context.close()  # type: ignore


if __name__ == "__main__":
    main()
