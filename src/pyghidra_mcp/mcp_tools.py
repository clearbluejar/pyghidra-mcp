"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import functools
import logging
from typing import Literal

from mcp.server.fastmcp import Context
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.models import (
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
    binary_name: str,
    name_or_address: str | list[str],
    ctx: Context,
    include_callees: bool = False,
    include_strings: bool = False,
    include_xrefs: bool = False,
) -> list[DecompiledFunction]:
    """Decompile function(s) to pseudo-C by name or address.

    Accepts a single target or a list for batch decompilation.
    Rich response flags attach callees, strings, and/or xrefs to each result.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []
    for target in targets:
        try:
            result = tools.decompile_function_by_name_or_addr(target)
            if include_callees:
                result.callees = tools.get_callees(target)
            if include_strings:
                result.referenced_strings = tools.get_referenced_strings(target)
            if include_xrefs:
                result.xrefs = tools.list_xrefs(target)
            results.append(result)
        except Exception as e:
            results.append(DecompiledFunction(name=target, code="", error=str(e)))
    return results


@mcp_error_handler
def search_symbols_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Search symbols by case-insensitive substring.

    Includes functions, labels, classes, namespaces, and variables.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_symbols_by_name(query, offset, limit)
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_functions_by_name(
    binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 25
) -> SymbolSearchResults:
    """Search functions only by case-insensitive substring (no labels/variables)."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_functions_by_name(query, offset, limit)
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: Literal["semantic", "literal"] = "semantic",
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    """Search decompiled pseudo-C code.

    Modes: semantic (vector similarity, default) or literal (exact match).
    Results include both mode counts.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.search_code(
        query=query,
        limit=limit,
        offset=offset,
        search_mode=SearchMode(search_mode),
        include_full_code=include_full_code,
        preview_length=preview_length,
        similarity_threshold=similarity_threshold,
    )


@mcp_error_handler
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List all binaries in the project with their status."""
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
                strings_collection=pi.strings is not None,
            )
        )
    return ProgramInfos(programs=program_infos)


@mcp_error_handler
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Get binary metadata: architecture, compiler, endianness, hashes, analysis counts."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    return program_info.metadata


@mcp_error_handler
async def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Delete a binary from the project."""
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
    """List exported symbols, optionally filtered by regex query."""
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
    """List imported symbols, optionally filtered by regex query."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    imports = tools.list_imports(query=query, offset=offset, limit=limit)
    return ImportInfos(imports=imports)


@mcp_error_handler
def list_xrefs(
    binary_name: str, name_or_address: str | list[str], ctx: Context
) -> list[CrossReferenceInfos]:
    """List cross-references to function(s), symbol(s), or address(es).

    Accepts a single target or a list for batch lookup.
    Suggests close matches on no exact hit.
    """
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[CrossReferenceInfos] = []
    for target in targets:
        try:
            cross_references = tools.list_xrefs(target)
            results.append(CrossReferenceInfos(target=target, cross_references=cross_references))
        except Exception as e:
            results.append(CrossReferenceInfos(target=target, cross_references=[], error=str(e)))
    return results


@mcp_error_handler
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Search for strings within a binary."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Read raw bytes at an address. Hex format supported (0x prefix optional)."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: Literal["calling", "called"] = "calling",
    display_type: Literal["flow", "flow_ends"] = "flow",
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    """Generate a MermaidJS call graph for a function."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.gen_callgraph(
        function_name_or_address=function_name,
        cg_direction=CallGraphDirection(direction),
        cg_display_type=CallGraphDisplayType(display_type),
        include_refs=True,
        max_depth=None,
        max_run_time=max_run_time,
        condense_threshold=condense_threshold,
        top_layers=top_layers,
        bottom_layers=bottom_layers,
    )


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> str:
    """Import a binary into the project from a file path."""
    # We would like to do context progress updates, but until that is more
    # widely supported by clients, we will resort to this
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    pyghidra_context.import_binary_backgrounded(binary_path)
    return (
        f"Importing {binary_path} in the background."
        "When ready, it will appear analyzed in binary list."
    )
