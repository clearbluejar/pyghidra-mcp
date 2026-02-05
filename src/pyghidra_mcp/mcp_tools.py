"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import functools
import logging

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
    BinaryMetadata,
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CrossReferenceInfos,
    DecompiledFunction,
    ExportInfos,
    ImportInfos,
    ProgramInfo,
    ProgramInfos,
    SearchMode,
    StringSearchResults,
    SymbolSearchResults,
)
from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)


def _get_action_name(func_name: str) -> str:
    """Derives a gerund action name from a function name."""
    action = func_name.replace("_", " ")
    words = action.split()
    if words and not words[0].endswith("ing"):
        first = words[0]
        if first.endswith("e"):
            words[0] = first[:-1] + "ing"
        else:
            words[0] = first + "ing"
    return " ".join(words)


def mcp_error_handler(func):
    """
    Decorator that provides centralized error handling for MCP tools.
    """
    action = _get_action_name(func.__name__)

    def handle_error(e):
        if isinstance(e, ValueError):
            return McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))
        if isinstance(e, McpError):
            return e
        return McpError(ErrorData(code=INTERNAL_ERROR, message=f"Error {action}: {e!s}"))

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    import asyncio

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# MCP Tool Implementations
# ---------------------------------------------------------------------------------


@mcp_error_handler
async def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompiles a function in a specified binary and returns its pseudo-C code.

    Args:
        binary_name: The name of the binary containing the function.
        name_or_address: The name or address of the function to decompile.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.decompile_function_by_name_or_addr(name_or_address)


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_symbols_by_name(query, offset, limit)
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: SearchMode = SearchMode.SEMANTIC,
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    """
    Perform a code search over a binary's decompiled pseudo C output.

    Supports two search modes:
    - **semantic**: Vector similarity search for meaning-based matching (default)
    - **literal**: Exact string matching using $contains for precise text matches

    Results always include counts to help
    decide if switching modes would yield better results

    For best results provide a short distinctive query such as a function
    signature or key logic snippet to minimize irrelevant matches.

    Args:
        binary_name: Name of the binary to search within.
        query: Code snippet, signature, or exact text to search for.
        limit: Maximum number of results to return (default: 5).
        offset: Number of results to skip for pagination (default: 0).
        search_mode: Search mode - 'semantic' or 'literal' (default: semantic).
        include_full_code: If True, return full function code. If False, return truncated preview.
        preview_length: Length of preview in characters when include_full_code=False (default: 500).
        similarity_threshold: Minimum similarity score (0.0-1.0) for semantic results
            (default: 0.0).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.search_code(
        query=query,
        limit=limit,
        offset=offset,
        search_mode=search_mode,
        include_full_code=include_full_code,
        preview_length=preview_length,
        similarity_threshold=similarity_threshold,
    )


@mcp_error_handler
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
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_infos = []
    for name, pi in pyghidra_context.programs.items():
        program_infos.append(
            ProgramInfo(
                name=name,
                file_path=str(pi.file_path) if pi.file_path else None,
                load_time=pi.load_time,
                analysis_complete=pi.analysis_complete,
                metadata={},
                code_collection=pi.code_collection is not None,
                strings_collection=pi.strings_collection is not None,
            )
        )
    return ProgramInfos(programs=program_infos)


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    metadata_dict = program_info.metadata
    return BinaryMetadata.model_validate(metadata_dict)


@mcp_error_handler
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Deletes a binary (program) from the project.

    Args:
        binary_name: The name of the binary to delete.
    """
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


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    exports = tools.list_exports(query=query, offset=offset, limit=limit)
    return ExportInfos(exports=exports)


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    imports = tools.list_imports(query=query, offset=offset, limit=limit)
    return ImportInfos(imports=imports)


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    cross_references = tools.list_cross_references(name_or_address)
    return CrossReferenceInfos(cross_references=cross_references)


@mcp_error_handler
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
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Reads raw bytes from memory at a specified address.

    Args:
        binary_name: The name of the binary to read bytes from.
        address: The memory address to read from (supports hex format with or without 0x prefix).
        size: The number of bytes to read (default: 32, max: 8192).
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
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
        binary_name: The name of the binary containing the function.
        function_name: The name of the function to generate the call graph for.
        direction: Direction of the call graph (calling or called).
        display_type: Format of the graph (flow, flow_ends).
        condense_threshold: Maximum number of edges before graph condensation is triggered.
        top_layers: Number of top layers to show in a condensed graph.
        bottom_layers: Number of bottom layers to show in a condensed graph.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
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


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> str:
    """Imports a binary from a designated path into the current Ghidra project.

    Args:
        binary_path: The path to the binary file to import.
    """
    # We would like to do context progress updates, but until that is more
    # widely supported by clients, we will resort to this
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    pyghidra_context.import_binary_backgrounded(binary_path)
    return (
        f"Importing {binary_path} in the background."
        "When ready, it will appear analyzed in binary list."
    )
