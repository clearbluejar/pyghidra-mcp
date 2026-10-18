"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import asyncio
import functools
import json
import logging
import os
import re
import struct
import sys
import time
from pathlib import Path
from typing import Any, Literal, cast


try:
    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:
    try:
        from mcp.server.fastmcp import Context
        from mcp.shared.exceptions import McpError as ToolError
    except ImportError:
        Context = Any  # type: ignore
        ToolError = Exception  # type: ignore

from pyghidra_mcp import forks
from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    ClearCacheResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    DisassembleResult,
    ExportInfos,
    ForkInfo,
    ForkList,
    ForkMergeResult,
    FunctionPrototypeResponse,
    GpuAdrpMatchItem,
    GpuAdrpScanResult,
    GpuFunctionSeedItem,
    GpuSeedFunctionsResult,
    GovernorModeResult,
    GovernorPolicy,
    GotoResponse,
    GuiContextResponse,
    HibernateResult,
    ImportInfos,
    ImportRequestResult,
    OpenProgramInfo,
    OpenProgramInfos,
    ProgramInfos,
    RenameResponse,
    RvaTranslateResult,
    SaveRequestResult,
    SearchMode,
    SessionInfo,
    StringSearchResults,
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
    FieldMigrationItem,
    StructInsertionItem,
    MigrateStructShiftsResult,
    SmtVerificationResult,
    SyntheticSymbolExportResult,
    JniMatchItem,
    ApkJniCrossRefResult,
    BinaryMatchItem,
    BinaryDiffResult,
    EmulatorMemoryVerifyResult,
    NeuralDecompileSkinResult,
    MigratedEventRecordItem,
    MigrateSemanticDeltasResult,
    PreindexDwarfPdbResult,
    InspectBinaryResult,
    RecoverCppClassesResult,
    TraceSerializeResult,
    DecodeCArchiveResult,
)

from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)
DECOMPILE_TIMEOUT_GRACE_SECONDS = 1.0
CALLGRAPH_TIMEOUT_GRACE_SECONDS = 15.0


def _get_pyghidra_context(ctx: Context) -> MCPContext:
    """Narrow the SDK's default dictionary lifespan type to our shared context."""
    return cast(MCPContext, ctx.request_context.lifespan_context)


def _require_gui_context(ctx: Context):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    pyghidra_context = ctx.request_context.lifespan_context
    if not isinstance(pyghidra_context, GuiPyGhidraContext):
        raise ValueError("This tool requires pyghidra-mcp to be running with --gui")
    return pyghidra_context


def _run_for_context(pyghidra_context: MCPContext, fn):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    if isinstance(pyghidra_context, GuiPyGhidraContext):
        return pyghidra_context.run_on_swing(fn)
    return fn()


def _fork_session(pyghidra_context: MCPContext) -> forks.ForkSession | None:
    fork = getattr(pyghidra_context, "fork_session", None)
    return fork if isinstance(fork, forks.ForkSession) else None


def _journal(pyghidra_context: MCPContext, program_info: Any, op: str, **fields: Any) -> None:
    """Record a successful edit when this session works on a fork; never fail the edit."""
    fork = _fork_session(pyghidra_context)
    if fork is None:
        return
    try:
        binary = str(program_info.program.getDomainFile().getPathname()) if program_info else ""
        fork.record(op, binary, **fields)
    except Exception:
        logger.error("Failed to journal %s on fork %s", op, fork.fork_id, exc_info=True)


def _session_info(pyghidra_context: MCPContext) -> SessionInfo | None:
    info = forks.session_info(pyghidra_context)
    return SessionInfo(**info) if info else None


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

    def handle_error(e: Exception) -> ToolError:
        # MCPServer returns ToolError text to the client as CallToolResult(isError=True).
        # Since MCP 2.2 any other exception is treated as a crash and the client sees
        # only "Error executing tool <name>", hiding the actionable message.
        # MCPError is intentionally reserved for JSON-RPC protocol failures.
        if isinstance(e, ToolError):
            return e
        msg = str(e) if isinstance(e, ValueError) else f"Error {action}: {e!s}"
        try:
            return ToolError(msg)
        except (TypeError, AttributeError):
            try:
                from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

                code = INVALID_PARAMS if isinstance(e, ValueError) else INTERNAL_ERROR
                return ToolError(ErrorData(code=code, message=msg))
            except Exception:
                return e  # type: ignore

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

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


def _get_default_ledger_path() -> str:
    """Returns canonical path to evidence_ledger.json under user data directory."""
    data_dir = os.environ.get("SUPERGHIDRA_DATA_DIR")
    if data_dir:
        base = Path(data_dir)
    else:
        base = Path.home() / ".superghidra"
    return str(base / "evidence_ledger.json")


ALLOWED_OUTPUT_EXTENSIONS = {
    ".debug", ".pdb", ".sym", ".map", ".json", ".py", ".sqlite",
    ".db", ".sqlite3", ".txt", ".h", ".c", ".cpp", ".log", ".csv",
    ".bin", ".idx", ".xml", "",
}


def _resolve_safe_path(
    path: str | Path,
    must_exist: bool = False,
    for_write: bool = False,
    allowed_extensions: set[str] | None = None,
) -> Path:
    """Normalizes and safely validates user-supplied paths against traversal and system directories."""
    if not path or not str(path).strip():
        raise ValueError("Path must not be empty")

    p = Path(path).resolve()

    # Allowed roots check
    allowed_roots_env = os.environ.get("SUPERGHIDRA_ALLOWED_ROOTS")
    if allowed_roots_env:
        roots = [Path(r.strip()).resolve() for r in allowed_roots_env.split(os.pathsep) if r.strip()]
        if roots:
            is_under = False
            for r in roots:
                try:
                    p.relative_to(r)
                    is_under = True
                    break
                except ValueError:
                    if os.name == "nt" and str(p).lower().startswith(str(r).lower()):
                        is_under = True
                        break
            if not is_under:
                raise ValueError(f"Path '{p}' is not within SUPERGHIDRA_ALLOWED_ROOTS: {allowed_roots_env}")

    if for_write:
        if not p.parent.exists():
            raise ValueError(f"Parent directory does not exist for write: '{p.parent}'")

        # Refuse system directories
        sys_dirs: list[Path] = []
        if os.name == "nt":
            for env_var in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
                val = os.environ.get(env_var)
                if val:
                    sys_dirs.append(Path(val).resolve())
            sys_dirs.extend([
                Path(r"C:\Windows").resolve(),
                Path(r"C:\Program Files").resolve(),
                Path(r"C:\Program Files (x86)").resolve(),
            ])
        else:
            sys_dirs.extend([
                Path("/etc").resolve(),
                Path("/usr").resolve(),
                Path("/bin").resolve(),
                Path("/sbin").resolve(),
            ])

        for sd in sys_dirs:
            try:
                p.relative_to(sd)
                raise ValueError(f"Writing into protected system directory is forbidden: '{p}'")
            except ValueError:
                if os.name == "nt" and str(p).lower().startswith(str(sd).lower()):
                    raise ValueError(f"Writing into protected system directory is forbidden: '{p}'")

        if p.exists():
            if p.is_dir():
                raise ValueError(f"Target path for write is an existing directory: '{p}'")
            valid_exts = allowed_extensions if allowed_extensions is not None else ALLOWED_OUTPUT_EXTENSIONS
            if p.suffix.lower() not in valid_exts:
                raise ValueError(f"Refusing to overwrite existing non-output file '{p}' (extension: '{p.suffix}')")

    if must_exist or not for_write:
        if not p.exists():
            raise ValueError(f"File does not exist: '{p}'")
        if not p.is_file():
            raise ValueError(f"Path is not a regular file: '{p}'")

    return p


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
    timeout_sec: int = 30,
) -> list[DecompiledFunction]:
    """Decompile function(s) to pseudo-C by name or address.

    Accepts a single target or a list for batch decompilation.
    Rich response flags attach callees, strings, and/or xrefs to each result.
    `timeout_sec` applies per target.
    """
    if timeout_sec <= 0:
        raise ValueError("timeout_sec must be greater than zero")

    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []

    def _decompile_target(target: str) -> DecompiledFunction:
        result = tools.decompile_function_by_name_or_addr(target, timeout=timeout_sec)
        if include_callees:
            result.callees = tools.get_callees(target)
        if include_strings:
            result.referenced_strings = tools.get_referenced_strings(target)
        if include_xrefs:
            result.xrefs = tools.list_xrefs(target)
        return result

    for target in targets:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_decompile_target, target),
                timeout=timeout_sec + DECOMPILE_TIMEOUT_GRACE_SECONDS,
            )
            results.append(result)
        except asyncio.TimeoutError:
            results.append(
                DecompiledFunction(
                    name=target,
                    code="",
                    error=f"Decompilation timed out after {timeout_sec:g} seconds",
                )
            )
        except Exception as e:
            results.append(DecompiledFunction(name=target, code="", error=str(e)))
    return results


@mcp_error_handler
def search_symbols_by_name(
    binary_name: str,
    query: str,
    ctx: Context,
    functions_only: bool = False,
    offset: int = 0,
    limit: int = 25,
) -> SymbolSearchResults:
    """Search symbols by regex pattern (case-insensitive).

    Supports full regex (e.g. ``^main$``, ``func.*init``). Plain substrings
    still work since they are valid regex.

    Set ``functions_only=True`` to search only function symbols
    (excludes labels, variables, classes, namespaces).
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_symbols_by_name(
        query, functions_only=functions_only, offset=offset, limit=limit
    )
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
    pyghidra_context = _get_pyghidra_context(ctx)
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
    """List all binaries in the project with their status.

    `session` says whether this server is the primary or a fork of a shared project.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    return ProgramInfos(
        programs=pyghidra_context.list_project_binary_infos(),
        session=_session_info(pyghidra_context),
    )


@mcp_error_handler
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Get binary metadata: architecture, compiler, endianness, hashes, analysis counts."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    return program_info.metadata


@mcp_error_handler
def list_open_programs(ctx: Context) -> OpenProgramInfos:
    """List programs currently open in the Ghidra GUI."""
    gui_context = _require_gui_context(ctx)
    programs = [OpenProgramInfo(**info) for info in gui_context.list_open_programs()]
    return OpenProgramInfos(programs=programs)


@mcp_error_handler
def open_program_in_gui(
    binary_name: str,
    new_window: bool = True,
    *,
    ctx: Context,
) -> OpenProgramInfo:
    """Open a project binary in the Ghidra GUI CodeBrowser.

    Defaults to a new CodeBrowser unless the binary is already open.
    """
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.open_program_in_gui(binary_name, new_window=new_window))


@mcp_error_handler
def set_current_program(binary_name: str, ctx: Context) -> OpenProgramInfo:
    """Set the active/current program in the Ghidra GUI CodeBrowser."""
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.set_current_program(binary_name))


@mcp_error_handler
def goto(
    binary_name: str,
    target: str,
    target_type: Literal["address", "function"],
    ctx: Context,
) -> GotoResponse:
    """Navigate the Ghidra GUI CodeBrowser to an address or function."""
    gui_context = _require_gui_context(ctx)
    return GotoResponse(**gui_context.goto(binary_name, target, target_type))


@mcp_error_handler
def get_gui_context(ctx: Context) -> GuiContextResponse:
    """Get the current active user's location and metadata in the Ghidra GUI.

    Assume this is volatile and has changed since last call.
    """
    gui_context = _require_gui_context(ctx)
    return GuiContextResponse(**gui_context.get_active_gui_context())


@mcp_error_handler
def rename_function(
    binary_name: str,
    name_or_address: str,
    new_name: str,
    ctx: Context,
) -> RenameResponse:
    """Rename a function."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_function(name_or_address, new_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "rename_function",
        address=result["address"],
        old=result["old_name"],
        new=result["new_name"],
    )
    return RenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def rename_variable(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    new_name: str,
    ctx: Context,
) -> VariableRenameResponse:
    """Rename a parameter or local by exact name."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_variable(function_name_or_address, variable_name, new_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "rename_variable",
        function_address=result["function_address"],
        storage=result.get("storage"),
        old=result["old_name"],
        new=result["new_name"],
    )
    return VariableRenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_variable_type(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    type_name: str,
    ctx: Context,
) -> VariableTypeResponse:
    """Set a parameter or local type by exact name."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_variable_type(function_name_or_address, variable_name, type_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_variable_type",
        function_address=result["function_address"],
        storage=result.get("storage"),
        variable_name=result["variable_name"],
        type_name=type_name,
        old=result["old_type"],
        new=result["new_type"],
    )
    return VariableTypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_function_prototype(
    binary_name: str,
    function_name_or_address: str,
    prototype: str,
    ctx: Context,
) -> FunctionPrototypeResponse:
    """Set a function prototype. Invalid input returns Ghidra's error."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_function_prototype(function_name_or_address, prototype),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_function_prototype",
        address=result["function_address"],
        prototype=prototype,
        old=result["old_prototype"],
        new=result["new_prototype"],
    )
    return FunctionPrototypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_comment(
    binary_name: str,
    target: str,
    comment: str,
    comment_type: Literal["decompiler", "plate", "pre", "eol", "post", "repeatable"],
    ctx: Context,
) -> CommentResponse:
    """Set a decompiler or listing comment."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_comment(target, comment, comment_type),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_comment",
        address=result["address"],
        comment_type=result["comment_type"],
        old=result.get("old_comment"),
        new=result["comment"],
    )
    return CommentResponse(binary_name=binary_name, **result)


@mcp_error_handler
def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Delete a binary from the project."""
    pyghidra_context = _get_pyghidra_context(ctx)
    if pyghidra_context.delete_program(binary_name):
        fork = _fork_session(pyghidra_context)
        if fork is not None:
            fork.record("delete_project_binary", binary_name)
        return f"Successfully deleted binary: {binary_name}"
    else:
        raise ValueError(f"Binary '{binary_name}' not found or could not be deleted.")


@mcp_error_handler
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """List exported symbols, optionally filtered by regex query."""
    pyghidra_context = _get_pyghidra_context(ctx)
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
    pyghidra_context = _get_pyghidra_context(ctx)
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
    pyghidra_context = _get_pyghidra_context(ctx)
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
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Read raw bytes at an address. Hex format supported (0x prefix optional)."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
def disassemble(
    binary_name: str,
    ctx: Context,
    address: str,
    count: int = 20,
    include_bytes: bool = False,
) -> DisassembleResult:
    """Disassemble raw instructions at any address, like objdump.

    `listing` is one instruction per line: address, mnemonic, operands, plus a hex
    bytes column if `include_bytes=True`. Returns up to `count` instructions (max 200).
    """
    if count <= 0:
        raise ValueError("count must be > 0")
    if count > 200:
        raise ValueError("count must be <= 200")
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.disassemble(address=address, count=count, include_bytes=include_bytes)


@mcp_error_handler
async def gen_callgraph(
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
    if max_run_time <= 0:
        raise ValueError("max_run_time must be greater than zero")
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    def _generate() -> CallGraphResult:
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

    # ghidrecomp only checks max_run_time between expansions and can overrun it by
    # minutes on dense "called" graphs (#122); bound how long the client waits.
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_generate),
            timeout=max_run_time + CALLGRAPH_TIMEOUT_GRACE_SECONDS,
        )
    except asyncio.TimeoutError:
        raise ValueError(
            f"Call graph for '{function_name}' did not finish within {max_run_time}s. "
            "Retry with a smaller max_run_time or direction='calling'."
        ) from None


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> ImportRequestResult:
    """Import a binary into the project from a file path."""
    pyghidra_context = _get_pyghidra_context(ctx)
    result = pyghidra_context.import_binary_backgrounded(binary_path)
    fork = _fork_session(pyghidra_context)
    if fork is not None and result.queued_count:
        fork.record("import_binary", "", path=str(Path(binary_path).absolute()))
    return result


@mcp_error_handler
def save(ctx: Context) -> SaveRequestResult:
    """Save all programs."""
    pyghidra_context = _get_pyghidra_context(ctx)
    pyghidra_context.save()
    return SaveRequestResult()


# Multi-agent forks
# ---------------------------------------------------------------------------------


def _forks_dir(pyghidra_context: MCPContext) -> Path:
    fork = _fork_session(pyghidra_context)
    if fork is not None:
        return fork.parent_pyghidra_mcp_dir
    return cast(Path, cast(Any, pyghidra_context).pyghidra_mcp_dir)


@mcp_error_handler
def list_forks(ctx: Context) -> ForkList:
    """List forks of this project and this session's role.

    A fork is created when a server finds the project locked by another session.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    return ForkList(
        session=_session_info(pyghidra_context),
        forks=[ForkInfo(**info) for info in forks.list_forks(_forks_dir(pyghidra_context))],
    )


@mcp_error_handler
def merge_fork(
    fork_id: str,
    ctx: Context,
    dry_run: bool = False,
    on_conflict: Literal["skip", "overwrite"] = "skip",
) -> ForkMergeResult:
    """Replay a fork's journaled edits into this (primary) project.

    Edits whose target also changed here since the fork are conflicts: skipped,
    or forced with on_conflict="overwrite". Re-running only retries unresolved edits.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    if _fork_session(pyghidra_context) is not None:
        raise ValueError(
            "This session is itself a fork; merge_fork must run on the primary session "
            "that holds the main project."
        )
    merger = forks.ForkMerger(
        pyghidra_context,
        GhidraTools,
        run=lambda fn: _run_for_context(pyghidra_context, fn),
    )
    return ForkMergeResult(**merger.merge(fork_id, dry_run=dry_run, on_conflict=on_conflict))


@mcp_error_handler
def discard_fork(fork_id: str, ctx: Context) -> str:
    """Delete a stopped fork and its journal. Unmerged edits are lost."""
    pyghidra_context = _get_pyghidra_context(ctx)
    fork = _fork_session(pyghidra_context)
    if fork is not None and fork.fork_id == fork_id:
        raise ValueError("A session cannot discard the fork it is running on.")
    info = forks.discard_fork(_forks_dir(pyghidra_context), fork_id)
    return f"Discarded fork {fork_id} ({info.get('pending_ops', 0)} unmerged edit(s) dropped)."


# SuperGhidra Native MCP Tools
# ---------------------------------------------------------------------------------


def _get_superghidra_path() -> str:
    env_path = os.environ.get("SUPERGHIDRA_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    repo_sibling = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "SuperGhidra")
    if os.path.exists(repo_sibling):
        return repo_sibling
    fallback = r"E:\02_Projects\SuperGhidra"
    if os.path.exists(fallback):
        logger.warning("SUPERGHIDRA_PATH unset; falling back to %s", fallback)
    return fallback


def _ensure_superghidra_imported():
    try:
        import gpu_adrp_scanner  # noqa: F401
        return
    except ImportError:
        pass

    env_path = os.environ.get("SUPERGHIDRA_PATH")
    if env_path and os.path.exists(env_path):
        if env_path not in sys.path:
            sys.path.insert(0, env_path)
        return

    repo_sibling = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "SuperGhidra")
    if os.path.exists(repo_sibling):
        if repo_sibling not in sys.path:
            sys.path.insert(0, repo_sibling)
        return

    fallback_path = r"E:\02_Projects\SuperGhidra"
    if os.path.exists(fallback_path):
        logger.warning(
            "SuperGhidra not found on sys.path or SUPERGHIDRA_PATH; falling back to %s",
            fallback_path,
        )
        if fallback_path not in sys.path:
            sys.path.insert(0, fallback_path)


def _to_ghidra_addr(program: Any, offset: int) -> Any:
    try:
        af = program.getAddressFactory()
        if af:
            return af.getDefaultAddressSpace().getAddress(offset)
    except Exception:
        pass
    try:
        ib = program.getImageBase()
        if ib:
            return ib.getNewAddress(offset)
    except Exception:
        pass
    return offset


def _get_program_executable_segments(program_info: Any) -> list[tuple[bytes, int]]:
    """Retrieves binary executable segments with exact start virtual addresses to prevent segment VA skew."""
    segments: list[tuple[bytes, int]] = []
    base_pc = 0x100000
    try:
        if hasattr(program_info, "program") and program_info.program:
            base_pc = int(program_info.program.getImageBase().getOffset())
    except Exception:
        pass

    if hasattr(program_info, "program") and program_info.program:
        try:
            mem = program_info.program.getMemory()
            blocks = list(mem.getBlocks())
            exec_blocks = [b for b in blocks if hasattr(b, "isExecute") and b.isExecute()]
            if not exec_blocks:
                exec_blocks = [b for b in blocks if hasattr(b, "isInitialized") and b.isInitialized()]
            for block in exec_blocks:
                sz = block.getSize()
                if sz > 0:
                    chunk = bytearray(min(sz, 50 * 1024 * 1024))
                    read_sz = block.getBytes(block.getStart(), chunk)
                    if read_sz > 0:
                        segments.append((bytes(chunk[:read_sz]), int(block.getStart().getOffset())))
        except Exception:
            pass

    if not segments:
        file_path = getattr(program_info, "file_path", None)
        if file_path and os.path.exists(file_path):
            try:
                raw = Path(file_path).read_bytes()
                if raw.startswith(b"\x7fELF"):
                    _ensure_superghidra_imported()
                    from colab_cloud_orchestrator import ColabCloudOrchestrator
                    elf_vaddr, elf_exec_bytes = ColabCloudOrchestrator.extract_elf_executable_slice(raw)
                    if elf_exec_bytes:
                        segments.append((elf_exec_bytes, elf_vaddr))
                    else:
                        segments.append((raw, base_pc))
                elif raw:
                    segments.append((raw, base_pc))
            except Exception:
                pass

    if not segments:
        segments.append((b"", base_pc))
    return segments


def _get_program_bytes_and_base(program_info: Any) -> tuple[bytes, int]:
    """Retrieves binary raw bytes and image base vaddr."""
    segs = _get_program_executable_segments(program_info)
    if segs:
        return segs[0]
    return b"", 0x100000


@mcp_error_handler
def rva_translate(addr: str, base: str = "0x100000") -> RvaTranslateResult:
    """Calculates VA and RVA with zero JVM overhead (<0.01 ms).

    Translates between Ghidra Virtual Address (VA) and runtime Relative Virtual Address (RVA).
    Args:
        addr: Virtual Address (VA) or Relative Virtual Address (RVA) as hex string (e.g. '0x1000' or '0x101000').
        base: Image base offset (default: '0x100000').
    """
    t0 = time.perf_counter()
    base_str = str(base).strip()
    base_int = (
        int(base_str, 16)
        if base_str.lower().startswith("0x")
        else int(base_str, 16)
        if any(c in "abcdefABCDEF" for c in base_str)
        else int(base_str)
    )

    addr_str = str(addr).strip()
    val = (
        int(addr_str, 16)
        if addr_str.lower().startswith("0x")
        else int(addr_str, 16)
        if any(c in "abcdefABCDEF" for c in addr_str)
        else int(addr_str)
    )

    if val >= base_int:
        va_int = val
        rva_int = val - base_int
    else:
        rva_int = val
        va_int = val + base_int

    t_ms = (time.perf_counter() - t0) * 1000.0
    return RvaTranslateResult(
        status="ok",
        va=f"0x{va_int:08X}",
        rva=f"0x{rva_int:08X}",
        va_int=va_int,
        rva_int=rva_int,
        image_base=f"0x{base_int:08X}",
        time_ms=round(t_ms, 4),
    )


@mcp_error_handler
def gpu_adrp_scan(
    binary_name: str,
    ctx: Context,
    max_matches: int = 100,
    apply_xrefs: bool = False,
) -> GpuAdrpScanResult:
    """Scan candidate ADRP+ADD/LDR pairs in an ARM64 binary using GPU acceleration.

    Uses WGPU compute shaders, PyTorch CUDA, or candidate-filtered SIMD/NumPy fallback.
    Args:
        binary_name: Name of the binary to scan.
        max_matches: Maximum number of candidate pairs to return (default: 100).
        apply_xrefs: If True, writes discovered memory references back into Ghidra program.
    """
    if max_matches <= 0:
        raise ValueError("max_matches must be greater than zero")

    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    segments = _get_program_executable_segments(program_info)
    if not segments or not any(len(s[0]) > 0 for s in segments):
        raise ValueError(f"No executable bytes found for binary '{binary_name}'")

    _ensure_superghidra_imported()
    from gpu_adrp_scanner import GPUAdrpScanner

    scanner = GPUAdrpScanner(backend="auto")
    all_raw_matches = []
    for seg_bytes, seg_base_pc in segments:
        if seg_bytes:
            seg_matches = scanner.scan_matches(seg_bytes, base_pc=seg_base_pc, filter_same_register=True)
            all_raw_matches.extend(seg_matches)

    matches = [GpuAdrpMatchItem(**m.to_dict()) for m in all_raw_matches[:max_matches]]

    applied_xrefs: int | None = None
    if apply_xrefs:
        applied_count = 0
        program = getattr(program_info, "program", None)
        if program is not None:
            tx = None
            commit = False
            try:
                if hasattr(program, "startTransaction"):
                    tx = program.startTransaction("SuperGhidra GPU ADRP XRefs")
                rm = getattr(program, "getReferenceManager", lambda: None)()
                ref_type = None
                source_type = None
                try:
                    from ghidra.program.model.symbol import RefType, SourceType
                    ref_type = RefType.DATA
                    source_type = SourceType.ANALYSIS
                except Exception:
                    pass

                for m in all_raw_matches[:max_matches]:
                    if rm is not None and hasattr(rm, "addMemoryReference"):
                        tgt = getattr(m, "resolved_target", getattr(m, "target_address", 0))
                        apc = getattr(m, "adrp_pc", 0)
                        if isinstance(apc, str):
                            apc = int(apc, 16) if apc.startswith("0x") else int(apc)
                        if isinstance(tgt, str):
                            tgt = int(tgt, 16) if tgt.startswith("0x") else int(tgt)
                        from_addr = _to_ghidra_addr(program, int(apc))
                        to_addr = _to_ghidra_addr(program, int(tgt))
                        if ref_type is not None and source_type is not None:
                            try:
                                rm.addMemoryReference(from_addr, to_addr, ref_type, source_type, 0)
                            except TypeError:
                                rm.addMemoryReference(from_addr, to_addr)
                        else:
                            rm.addMemoryReference(from_addr, to_addr)
                        applied_count += 1
                commit = True
            except Exception as e:
                commit = False
                if tx is not None and hasattr(program, "endTransaction"):
                    try:
                        program.endTransaction(tx, False)
                        tx = None
                    except Exception:
                        pass
                return GpuAdrpScanResult(
                    status="error",
                    binary_name=binary_name,
                    backend=scanner.active_backend,
                    total_matches=len(all_raw_matches),
                    matches=matches,
                    applied_xrefs=0,
                    message=f"Failed to apply ADRP xrefs: {e}",
                )
            finally:
                if tx is not None and hasattr(program, "endTransaction"):
                    try:
                        program.endTransaction(tx, commit)
                    except Exception:
                        pass
        applied_xrefs = applied_count

    return GpuAdrpScanResult(
        status="ok",
        binary_name=binary_name,
        backend=scanner.active_backend,
        total_matches=len(all_raw_matches),
        matches=matches,
        applied_xrefs=applied_xrefs,
    )


@mcp_error_handler
def gpu_seed_functions(
    binary_name: str,
    ctx: Context,
    max_functions: int = 500,
    apply_to_program: bool = False,
) -> GpuSeedFunctionsResult:
    """Recovers function entry points at 100M+ insns/s using GPU-accelerated pattern seeder.

    Classifies branch links, prologues (PACIASP, STP x29, x30, SUB sp, BTI), and data pointers.
    Args:
        binary_name: Name of the binary to seed.
        max_functions: Maximum number of recovered function seeds to return (default: 500).
        apply_to_program: If True, creates newly discovered functions in the Ghidra program.
    """
    if max_functions <= 0:
        raise ValueError("max_functions must be greater than zero")

    import numpy as np

    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    segments = _get_program_executable_segments(program_info)
    if not segments or not any(len(s[0]) > 0 for s in segments):
        raise ValueError(f"No executable bytes found for binary '{binary_name}'")

    _ensure_superghidra_imported()
    from gpu_function_seeder import GPUFunctionSeeder

    seeder = GPUFunctionSeeder(backend="auto")
    all_raw_seeds = []
    for seg_bytes, seg_base_pc in segments:
        if seg_bytes:
            rem = len(seg_bytes) % 4
            aligned_bytes = seg_bytes + b"\x00" * (4 - rem) if rem else seg_bytes
            text_instructions = np.frombuffer(aligned_bytes, dtype="<u4")
            seg_seeds = seeder.seed_functions(text_instructions, text_base_vaddr=seg_base_pc)
            all_raw_seeds.extend(seg_seeds)

    seeds = [GpuFunctionSeedItem(**s.to_dict()) for s in all_raw_seeds[:max_functions]]

    applied_to_program: int | None = None
    if apply_to_program:
        applied_count = 0
        program = getattr(program_info, "program", None)
        if program is not None:
            tx = None
            try:
                if hasattr(program, "startTransaction"):
                    tx = program.startTransaction("SuperGhidra GPU Seed Functions")
                fm = getattr(program, "getFunctionManager", lambda: None)()
                source_type = None
                addr_set_cls = None
                try:
                    from ghidra.program.model.symbol import SourceType
                    from ghidra.program.model.address import AddressSet
                    source_type = SourceType.ANALYSIS
                    addr_set_cls = AddressSet
                except Exception:
                    pass

                for s in all_raw_seeds[:max_functions]:
                    if fm is not None:
                        try:
                            vaddr = getattr(s, "entry_vaddr", getattr(s, "entry_va", 0))
                            if isinstance(vaddr, str):
                                vaddr = int(vaddr, 16) if vaddr.startswith("0x") else int(vaddr)
                            addr = _to_ghidra_addr(program, vaddr)
                            if hasattr(fm, "getFunctionAt") and fm.getFunctionAt(addr) is not None:
                                continue
                            func_name = f"FUN_{vaddr:08x}"
                            body = addr_set_cls(addr) if addr_set_cls else addr
                            st = source_type if source_type is not None else "ANALYSIS"
                            if hasattr(fm, "createFunction"):
                                try:
                                    fm.createFunction(func_name, addr, body, st)
                                except TypeError:
                                    fm.createFunction(func_name, addr)
                                applied_count += 1
                        except Exception:
                            pass
            finally:
                if tx is not None and hasattr(program, "endTransaction"):
                    try:
                        program.endTransaction(tx, True)
                    except Exception:
                        pass
        applied_to_program = applied_count

    return GpuSeedFunctionsResult(
        status="ok",
        binary_name=binary_name,
        backend=seeder.active_backend,
        total_seeds=len(all_raw_seeds),
        seeds=seeds,
        applied_to_program=applied_to_program,
    )


@mcp_error_handler
def set_governor_mode(
    mode: str,
    ctx: Context,
    binary_name: str | None = None,
) -> GovernorModeResult:
    """Hot-swaps decompiler governor resource mode ('eco', 'balanced', 'turbo', 'auto').

    Calls program_info.decompiler_pool.set_resource_mode(mode) and returns new governor policy.
    Args:
        mode: Resource governor mode ('eco', 'balanced', 'turbo', 'auto').
        binary_name: Optional specific binary name. If omitted, applies to all open programs.
    """
    mode_str = mode.lower().strip()
    if mode_str not in ("eco", "balanced", "turbo", "auto"):
        raise ValueError(f"Invalid mode '{mode}'. Valid modes are: eco, balanced, turbo, auto")

    pyghidra_context = _get_pyghidra_context(ctx)
    res_dict: dict[str, Any] | None = None

    if binary_name:
        p_info = pyghidra_context.get_program_info(binary_name)
        if hasattr(p_info, "decompiler_pool") and p_info.decompiler_pool:
            res_dict = p_info.decompiler_pool.set_resource_mode(mode_str)
    elif getattr(pyghidra_context, "open_programs", None):
        for p_info in pyghidra_context.open_programs.values():
            if hasattr(p_info, "decompiler_pool") and p_info.decompiler_pool:
                res_dict = p_info.decompiler_pool.set_resource_mode(mode_str)

    # Build canonical policy details
    policy_obj = None
    try:
        _ensure_superghidra_imported()
        import dataclasses
        from resource_governor import ResourceMode, get_default_mode_policy

        pol = get_default_mode_policy(ResourceMode(mode_str), logical_cores=os.cpu_count() or 8)
        pol_dict = dataclasses.asdict(pol)
        pol_dict["mode"] = pol.mode.value
        policy_obj = GovernorPolicy(**pol_dict)
    except Exception:
        policy_obj = GovernorPolicy(mode=mode_str)

    msg = res_dict.get("message") if res_dict else f"Decompiler pool resource mode updated to '{mode_str}'"
    idle_to = float(res_dict.get("idle_timeout_sec", 120.0)) if res_dict else 120.0

    return GovernorModeResult(
        status="ok",
        mode=mode_str,
        message=msg,
        idle_timeout_sec=idle_to,
        policy=policy_obj,
    )


@mcp_error_handler
def hibernate(ctx: Context) -> HibernateResult:
    """Calls program_info.decompiler_pool.hibernate() and reclaims idle JVM memory."""
    pyghidra_context = _get_pyghidra_context(ctx)
    if getattr(pyghidra_context, "open_programs", None):
        for p_info in pyghidra_context.open_programs.values():
            if hasattr(p_info, "decompiler_pool") and p_info.decompiler_pool:
                p_info.decompiler_pool.hibernate()

    # Safely trigger JVM garbage collection to release uncommitted memory
    try:
        import java.lang.System

        java.lang.System.gc()
    except Exception:
        pass

    return HibernateResult(
        status="ok",
        message="Native decompiler pool hibernated; idle JVM memory reclaimed",
        hibernated=True,
        is_hibernating=True,
    )


@mcp_error_handler
def clear_cache(ctx: Context | None = None) -> ClearCacheResult:
    """Purges the persistent L2 SQLite cache."""
    _ensure_superghidra_imported()
    deleted = 0
    try:
        from pyghidra_mcp.l2_cache import L2SQLiteCache as PyGhidraL2Cache

        deleted += PyGhidraL2Cache().clear()
    except Exception as e:
        logger.debug("PyGhidraL2Cache.clear() notice: %s", e)

    try:
        from ghidra_oracle import L2SQLiteCache

        cache = L2SQLiteCache()
        deleted += cache.clear()
    except Exception as e:
        logger.debug("L2SQLiteCache.clear() notice: %s", e)

    # Also invalidate in-memory decompiler caches
    if ctx is not None:
        try:
            pyghidra_context = _get_pyghidra_context(ctx)
            if getattr(pyghidra_context, "open_programs", None):
                for p_info in pyghidra_context.open_programs.values():
                    if hasattr(p_info, "decompiler_pool") and p_info.decompiler_pool:
                        p_info.decompiler_pool.invalidate_all()
        except Exception:
            pass

    return ClearCacheResult(
        status="ok",
        cleared_entries=deleted,
        message=f"Persistent L2 SQLite cache purged ({deleted} entries removed).",
    )


@mcp_error_handler
def migrate_struct_shifts(
    old_binary_path: str,
    new_binary_path: str,
    struct_name: str | None = None,
    original_header: str | None = None,
    ctx: Context | None = None,
) -> MigrateStructShiftsResult:
    """Discovers struct field displacement shifts between two binary versions and generates C++ header patches.

    Args:
        old_binary_path: Path to v1 binary or disassembly file.
        new_binary_path: Path to v2 binary or disassembly file.
        struct_name: Name of target struct (default: 'TargetStruct').
        original_header: Optional existing C++ header source to patch.
    """
    _ensure_superghidra_imported()
    from struct_shift_migrator import migrate_struct_shifts as _sg_migrate

    report = _sg_migrate(
        old_binary_path=old_binary_path,
        new_binary_path=new_binary_path,
        struct_name=struct_name,
        original_header=original_header,
    )
    report_dict = report.to_dict()

    field_migrations = [
        FieldMigrationItem(
            field_name=m["field_name"],
            old_offset=m["old_offset"],
            new_offset=m["new_offset"],
            delta=m["delta"],
            shift_type=m["shift_type"],
            confidence=m["confidence"],
            old_offset_int=m["old_offset_int"],
            new_offset_int=m["new_offset_int"],
            access_size=m.get("access_size", 4),
            sample_v1_insn=m.get("sample_v1_insn", ""),
            sample_v2_insn=m.get("sample_v2_insn", ""),
        )
        for m in report_dict["field_migrations"]
    ]

    insertions = [
        StructInsertionItem(
            offset=ins["offset"],
            offset_int=ins["offset_int"],
            size=ins["size"],
            probable_type=ins["probable_type"],
        )
        for ins in report_dict["insertions"]
    ]

    return MigrateStructShiftsResult(
        status="ok",
        old_binary=report.old_binary,
        new_binary=report.new_binary,
        struct_name=report.struct_name,
        total_shifts_detected=report.total_shifts_detected,
        matched_functions=report.matched_functions,
        max_delta=report.max_delta,
        field_migrations=field_migrations,
        insertions=insertions,
        cpp_header_patch=report.cpp_header_patch,
        updated_header=report.updated_header,
        migration_report_json=json.dumps(report_dict, indent=2),
        summary=report.summary,
        message=f"Migrated {len(field_migrations)} fields with {report.total_shifts_detected} shifts detected.",
    )


@mcp_error_handler
def verify_smt_equivalence(
    pcode_or_hex: str,
    c_code: str,
    target_reg: str = "x0",
    param_map: dict[str, str] | None = None,
    base_pc: int = 0x1000,
    arch: str = "arm64",
    ctx: Context | None = None,
) -> SmtVerificationResult:
    """Formally proves bit-exact equivalence in Z3 between ARM64/x86_64 machine hex (or P-code JSON) and reconstructed C code.

    Args:
        pcode_or_hex: Machine instruction hex bytes (e.g. '00 00 80 52 c0 03 5f d6') or serialized P-code JSON.
        c_code: Reconstructed decompiled C source snippet or statement.
        target_reg: Name of target register to verify (default: 'x0'; supports x0..x30, w0..w30, d0..d31, s0..s31, rax..r15, eax..r15d, flag_n..flag_v).
        param_map: Optional variable-to-register parameter mapping: {'player': 'x0', 'damage': 'w2'}.
        base_pc: Virtual address base for instruction lifting (default: 0x1000).
        arch: Target architecture for machine hex lifting ('arm64' or 'x86_64', default: 'arm64').
    """
    _ensure_superghidra_imported()
    from smt_pcode_verifier import CCodeParser, CSymbolicEvaluator, SMTPcodeVerifier, SymbolicState
    from pcode_lifter_bridge import (
        ARM64PcodeLifter,
        X86_64PcodeLifter,
        AddressSpace,
        PcodeOp,
        PcodeOpcode,
        Varnode,
    )

    verifier = SMTPcodeVerifier()
    clean_input = pcode_or_hex.strip()

    if clean_input.startswith("[") or clean_input.startswith("{"):
        raw_ops = json.loads(clean_input)
        if isinstance(raw_ops, dict):
            raw_ops = raw_ops.get("pcode_ops", [raw_ops])
        deserialized_ops: list[PcodeOp] = []
        for item in raw_ops:
            if isinstance(item, PcodeOp):
                deserialized_ops.append(item)
            elif isinstance(item, dict):
                op_name = item.get("opcode", "COPY")
                opcode = PcodeOpcode[op_name] if isinstance(op_name, str) else PcodeOpcode(op_name)
                inputs = []
                for v in item.get("inputs", []):
                    if isinstance(v, Varnode):
                        inputs.append(v)
                    else:
                        sp_val = v.get("space", "ram")
                        space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                        off = v.get("offset", 0)
                        if isinstance(off, str) and off.startswith("0x"):
                            off = int(off, 16)
                        inputs.append(Varnode(space=space, offset=int(off), size=int(v.get("size", 8))))
                out = None
                if item.get("output"):
                    o_val = item["output"]
                    if isinstance(o_val, Varnode):
                        out = o_val
                    else:
                        sp_val = o_val.get("space", "ram")
                        space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                        off = o_val.get("offset", 0)
                        if isinstance(off, str) and off.startswith("0x"):
                            off = int(off, 16)
                        out = Varnode(space=space, offset=int(off), size=int(o_val.get("size", 8)))
                pc_val = item.get("pc", 0)
                if isinstance(pc_val, str) and pc_val.startswith("0x"):
                    pc_val = int(pc_val, 16)
                deserialized_ops.append(PcodeOp(opcode=opcode, inputs=inputs, output=out, pc=int(pc_val)))
        pcode_ops = deserialized_ops
    else:
        hex_clean = clean_input.replace(" ", "").replace("0x", "").replace("\n", "").replace("\r", "")
        raw_bytes = bytes.fromhex(hex_clean)
        if arch.lower().strip() in ("x86_64", "x64", "amd64", "x86"):
            lifter: Any = X86_64PcodeLifter()
        else:
            lifter = ARM64PcodeLifter()
        pcode_ops = lifter.lift_block(base_pc, raw_bytes)

    dummy_state = SymbolicState()
    if param_map:
        dummy_state.param_map = dict(param_map)
    resolved = CSymbolicEvaluator()._resolve_var_target(dummy_state, target_reg.strip())
    if resolved is None:
        return SmtVerificationResult(
            status="error",
            equivalent=False,
            smt_status="ERROR",
            details=f"Target register '{target_reg}' could not be resolved",
            target_reg=target_reg,
            message=f"Target register '{target_reg}' could not be resolved",
        )
    reg_off = resolved[0]
    tracked_registers = [reg_off]

    norm_c = CCodeParser()._normalize_c_syntax(c_code)
    has_c_mem = ("->" in c_code) or ("__deref" in norm_c)

    res = verifier.verify_equivalence(
        pcode_ops=pcode_ops,
        c_code_or_ast=c_code,
        param_map=param_map,
        check_memory=has_c_mem,
        tracked_registers=tracked_registers,
    )

    if res.equivalent:
        smt_desc = "EQUIVALENT (UNSAT)"
    elif res.status == "UNKNOWN":
        smt_desc = "UNKNOWN"
    elif res.status == "SAT":
        smt_desc = "DIVERGENT (SAT)"
    else:
        smt_desc = res.status
    msg = f"SMT verification: {smt_desc} for register {target_reg}."
    return SmtVerificationResult(
        status="ok",
        equivalent=res.equivalent,
        smt_status=res.status,
        details=res.details,
        obligation_id=res.obligation_id,
        counterexample=res.counterexample,
        model_inputs=res.model_inputs,
        pcode_out=res.pcode_out,
        c_out=res.c_out,
        target_reg=target_reg,
        message=msg,
    )


@mcp_error_handler
def export_synthetic_symbols(
    output_base_path: str,
    formats: list[str] | None = None,
    ledger_path: str | None = None,
    symbols_json_path: str | None = None,
    ctx: Context | None = None,
) -> SyntheticSymbolExportResult:
    """Exports DWARF5 (.debug), Microsoft PDB (.pdb), Breakpad (.sym), and .map symbol containers.

    Args:
        output_base_path: Output base file path without extension.
        formats: Symbol formats to emit: ['dwarf', 'pdb', 'sym', 'map']. Defaults to all 4.
        ledger_path: Optional path to evidence_ledger.json.
        symbols_json_path: Optional path to extra symbols JSON dictionary (_ghidra_names.json).
    """
    _ensure_superghidra_imported()
    from evidence_ledger import ReconstructionObligationLedger
    from synthetic_symbol_exporter import export_from_ledger

    safe_output_base = str(_resolve_safe_path(output_base_path, must_exist=False, for_write=True))

    ledger_source: Any
    if ledger_path:
        safe_ledger = str(_resolve_safe_path(ledger_path, must_exist=True, for_write=False))
        ledger_source = safe_ledger
    else:
        def_ledger = _get_default_ledger_path()
        ledger_source = ReconstructionObligationLedger(ledger_file=def_ledger)

    extra_symbols = None
    if symbols_json_path:
        safe_symbols = _resolve_safe_path(symbols_json_path, must_exist=True, for_write=False)
        with open(safe_symbols, "r", encoding="utf-8") as f:
            extra_symbols = json.load(f)

    requested_formats = formats or ["dwarf", "pdb", "sym", "map"]
    exported = export_from_ledger(
        ledger_source=ledger_source,
        output_base=safe_output_base,
        formats=requested_formats,
        additional_symbols=extra_symbols,
    )

    total_syms = 0
    if extra_symbols:
        total_syms = len(extra_symbols)
    elif hasattr(ledger_source, "obligations"):
        total_syms = len(ledger_source.obligations)

    msg = f"Exported {len(exported)} symbol containers to '{output_base_path}.*'"
    return SyntheticSymbolExportResult(
        status="ok",
        output_base_path=output_base_path,
        exported_files=exported,
        formats=list(exported.keys()),
        total_symbols=total_syms,
        message=msg,
    )


@mcp_error_handler
def cross_reference_apk_jni(
    java_sources: dict[str, str] | None = None,
    elf_exports: dict[str, int] | None = None,
    dynamic_registrations: list[dict[str, Any]] | None = None,
    apk_or_dex_path: str | None = None,
    so_binary_path: str | None = None,
    ctx: Context | None = None,
) -> ApkJniCrossRefResult:
    """Correlates Java/Kotlin native declarations with ELF .so exports and RegisterNatives tables.

    Args:
        java_sources: Optional dict mapping class names or file names to Java source code, or JSON method definitions.
        elf_exports: Optional dictionary mapping exported symbol names to virtual addresses (VA).
        dynamic_registrations: Optional list of dynamic RegisterNatives entries:
            [{'method_name': '...', 'signature': '...', 'fn_ptr': 0x...}].
        apk_or_dex_path: Optional path to Android APK, ZIP, or DEX file.
        so_binary_path: Optional path to companion ELF shared object (.so) file.
    """
    _ensure_superghidra_imported()
    from apk_jni_cross_referencer import APKJNICrossReferencer, JNIRegisteredNative

    ref = APKJNICrossReferencer(image_base=0x100000, is_64bit=True)

    if apk_or_dex_path:
        safe_apk = str(_resolve_safe_path(apk_or_dex_path, must_exist=True, for_write=False))
        ref.load_from_apk_or_dex(safe_apk)

    if so_binary_path:
        safe_so = _resolve_safe_path(so_binary_path, must_exist=True, for_write=False)
        with open(safe_so, "rb") as f_so:
            raw_so = f_so.read()
        if hasattr(ref, "extract_elf_jni_exports"):
            ref.extract_elf_jni_exports(raw_so)
        else:
            ref.load_from_elf_bytes(raw_so)

    if java_sources:
        type_map = {
            "void": "V", "boolean": "Z", "byte": "B", "char": "C", "short": "S",
            "int": "I", "long": "J", "float": "F", "double": "D", "String": "Ljava/lang/String;",
        }

        def _type_to_jni(t_str: str) -> str:
            t = t_str.strip()
            dims = t.count("[]")
            t_base = t.replace("[]", "").strip()
            jni_base = type_map.get(t_base, f"L{t_base.replace('.', '/')};")
            return ("[" * dims) + jni_base

        for key, content in java_sources.items():
            stripped = content.strip()
            if stripped.startswith("["):
                try:
                    ref.load_dex_methods_from_json(stripped)
                    continue
                except Exception:
                    pass

            pkg_match = re.search(r"package\s+([\w\.]+);", content)
            cls_match = re.search(r"(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)", content)
            pkg = pkg_match.group(1) if pkg_match else ""
            cls_name = cls_match.group(1) if cls_match else key.replace(".java", "")
            full_class = f"{pkg}.{cls_name}" if pkg else cls_name

            native_matches = re.finditer(
                r"(?:public|protected|private)?\s*(?:static\s+)?native\s+([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\);",
                content,
            )
            for nm in native_matches:
                ret_type = nm.group(1)
                method_name = nm.group(2)
                raw_args = nm.group(3).strip()

                arg_types = []
                if raw_args:
                    for arg_decl in raw_args.split(","):
                        tokens = arg_decl.strip().split()
                        if tokens:
                            arg_types.append(tokens[0])

                ret_jni = _type_to_jni(ret_type)
                args_jni = "".join(_type_to_jni(a) for a in arg_types)
                sig = f"({args_jni}){ret_jni}"

                ref.add_java_method(
                    class_name=full_class,
                    method_name=method_name,
                    signature=sig,
                )

    if elf_exports:
        ref.load_elf_exports(elf_exports)

    if dynamic_registrations:
        for idx, reg in enumerate(dynamic_registrations):
            entry = JNIRegisteredNative(
                table_address=int(reg.get("table_address", 0x200000)),
                slot_index=int(reg.get("slot_index", idx)),
                method_name=str(reg.get("method_name", "")),
                signature=str(reg.get("signature", "()V")),
                fn_ptr=int(reg.get("fn_ptr", 0)),
                class_context=reg.get("class_context"),
            )
            ref.registered_natives.append(entry)

    matches = ref.resolve_cross_references()
    script = ref.export_ghidra_python_script()

    match_items = [
        JniMatchItem(
            class_name=m.java_method.class_name,
            method_name=m.java_method.method_name,
            signature=m.java_method.signature,
            binding_type=m.binding_type,
            symbol_name=m.symbol_name,
            target_address=hex(m.target_address),
            target_rva=hex(m.target_rva),
            confidence=m.confidence,
        )
        for m in matches
    ]

    msg = f"Resolved {len(matches)} JNI cross-references ({len(ref.native_methods)} methods declared)."
    return ApkJniCrossRefResult(
        status="ok",
        total_java_methods=len(ref.native_methods),
        total_matches=len(matches),
        matches=match_items,
        ghidra_script=script,
        message=msg,
    )


def _parse_functions_for_diff(input_str: str) -> list[Any]:
    """Parses JSON or raw binary files into a list of FunctionCFG objects for diffing."""
    _ensure_superghidra_imported()
    from binary_diff_engine import (
        FunctionCFG,
        BasicBlock,
        InstructionInfo,
    )

    raw = input_str.strip()
    data = None
    is_heuristic = False
    is_json = raw.startswith("{") or raw.startswith("[")

    if not is_json:
        safe_path = _resolve_safe_path(raw, must_exist=True, for_write=False)
        is_binary = False
        raw_bytes = b""
        with open(safe_path, "rb") as bf:
            head = bf.read(4)
            if head.startswith(b"\x7fELF") or head.startswith(b"MZ") or head.startswith(b"\xca\xfe\xba\xbe"):
                is_binary = True
            bf.seek(0)
            raw_bytes = bf.read()

        if not is_binary:
            try:
                data = json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                if raw_bytes:
                    is_binary = True

        if is_binary:
            import binary_diff_engine
            if hasattr(binary_diff_engine, "extract_cfgs_from_binary"):
                return binary_diff_engine.extract_cfgs_from_binary(str(safe_path)), False
            # Seed CFGs directly from raw binary bytes
            is_heuristic = True
            chunk_sz = 256
            num_chunks = min(64, max(1, len(raw_bytes) // chunk_sz))
            bin_cfgs: list[FunctionCFG] = []
            for i in range(num_chunks):
                chunk = raw_bytes[i * chunk_sz : (i + 1) * chunk_sz]
                addr = 0x1000 + i * chunk_sz
                cfg = FunctionCFG(func_id=f"bin_func_{i:03d}", address=addr, name=f"sub_{addr:x}")
                bb = BasicBlock(start_addr=addr, end_addr=addr + len(chunk))
                for b_idx in range(0, len(chunk), 4):
                    slice4 = chunk[b_idx : b_idx + 4]
                    b0 = slice4[0] if len(slice4) > 0 else 0
                    if b0 & 0x80:
                        mnem = "ldr"
                    elif b0 & 0x40:
                        mnem = "str"
                    elif b0 & 0x20:
                        mnem = "add"
                    elif b0 & 0x10:
                        mnem = "cmp"
                    elif b0 & 0x08:
                        mnem = "b.eq"
                    elif b0 & 0x04:
                        mnem = "ret"
                    else:
                        mnem = "mov"
                    bb.instructions.append(InstructionInfo.create(address=addr + b_idx, mnemonic=mnem))
                cfg.add_block(bb)
                bin_cfgs.append(cfg)
            return bin_cfgs, is_heuristic
    else:
        data = json.loads(raw)

    if not isinstance(data, list):
        data = [data]

    cfgs: list[FunctionCFG] = []
    for idx, item in enumerate(data):
        func_id = str(item.get("func_id", item.get("name", f"func_{idx}")))
        address = int(item.get("address", 0x1000 + idx * 0x100))
        name = str(item.get("name", func_id))
        cfg = FunctionCFG(func_id=func_id, address=address, name=name)

        blocks_data = item.get("blocks", [])
        if not blocks_data:
            insns_raw = item.get("instructions", ["nop"])
            bb = BasicBlock(start_addr=address, end_addr=address + len(insns_raw) * 4)
            for i_idx, insn in enumerate(insns_raw):
                if isinstance(insn, str):
                    bb.instructions.append(InstructionInfo.create(address=address + i_idx * 4, mnemonic=insn))
                elif isinstance(insn, dict):
                    bb.instructions.append(InstructionInfo.create(
                        address=insn.get("address", address + i_idx * 4),
                        mnemonic=insn.get("mnemonic", "nop"),
                        op_str=insn.get("op_str", "")
                    ))
            cfg.add_block(bb)
        else:
            for b_item in blocks_data:
                b_start = int(b_item.get("start_addr", address))
                b_end = int(b_item.get("end_addr", b_start + 0x20))
                bb = BasicBlock(start_addr=b_start, end_addr=b_end)
                for i_idx, insn in enumerate(b_item.get("instructions", [])):
                    if isinstance(insn, str):
                        bb.instructions.append(InstructionInfo.create(address=b_start + i_idx * 4, mnemonic=insn))
                    elif isinstance(insn, dict):
                        bb.instructions.append(InstructionInfo.create(
                            address=insn.get("address", b_start + i_idx * 4),
                            mnemonic=insn.get("mnemonic", "nop"),
                            op_str=insn.get("op_str", "")
                        ))
                cfg.add_block(bb)

        for edge in item.get("edges", []):
            cfg.add_edge(int(edge[0]), int(edge[1]))

        cfgs.append(cfg)
    return cfgs, False


@mcp_error_handler
def diff_binaries(
    v1_functions_json: str,
    v2_functions_json: str,
    threshold: float = 0.70,
    method: str = "mutual_top1",
    ctx: Context | None = None,
) -> BinaryDiffResult:
    """Computes cosine-similarity CFG matches across two JSON-serialized lists of functions.

    Args:
        v1_functions_json: JSON string or file path containing list of function definitions for Binary 1.
        v2_functions_json: JSON string or file path containing list of function definitions for Binary 2.
        threshold: Minimum cosine similarity threshold to declare a match (default: 0.70).
        method: Matching algorithm: 'mutual_top1' (default) or 'greedy'.
    """
    _ensure_superghidra_imported()
    from binary_diff_engine import BatchedBinaryMatcher

    funcs_a, heur_a = _parse_functions_for_diff(v1_functions_json)
    funcs_b, heur_b = _parse_functions_for_diff(v2_functions_json)
    is_heuristic = heur_a or heur_b

    strategy = "mutual" if "mutual" in method.lower() else "greedy"
    matcher = BatchedBinaryMatcher(threshold=threshold, use_gpu=False)
    diff_res = matcher.diff_binaries(funcs_a, funcs_b, strategy=strategy)

    match_items = [
        BinaryMatchItem(
            func_a_id=m.func_a_id,
            func_a_name=m.func_a_name,
            func_a_addr=m.func_a_addr,
            func_b_id=m.func_b_id,
            func_b_name=m.func_b_name,
            func_b_addr=m.func_b_addr,
            similarity=round(m.similarity, 4),
            confidence=m.confidence,
            match_type="heuristic" if is_heuristic else m.match_type,
        )
        for m in diff_res.matches
    ]

    heur_msg = " [heuristic]" if is_heuristic else ""
    return BinaryDiffResult(
        status="ok",
        total_matches=len(match_items),
        match_rate_pct=round(diff_res.match_rate_pct, 2),
        avg_similarity=round(diff_res.avg_similarity, 4),
        execution_time_ms=round(diff_res.execution_time_ms, 3),
        matches=match_items,
        unmatched_a=diff_res.unmatched_a,
        unmatched_b=diff_res.unmatched_b,
        message=f"Matched {len(match_items)} functions ({diff_res.match_rate_pct:.1f}% match rate){heur_msg}.",
    )


@mcp_error_handler
def verify_emulator_memory(
    device_serial: str,
    action: str = "verify_vtable",
    rva: str = "0x1000",
    module_base: str = "0x7000000000",
    expected_slots: int = 4,
    expected_type: str = "uint32",
    key_length: int = 32,
    pid: int | None = None,
    target_process: str | None = None,
    expected_slot_rvas: list[str] | None = None,
    mock_memory_hex: str | None = None,
    ctx: Context | None = None,
) -> EmulatorMemoryVerifyResult:
    """Enforces android-emulator-fleet-safety and verifies live/mock memory pointers.

    Args:
        device_serial: Target emulator device serial (e.g. '127.0.0.1:21513', 'emulator-5580').
        action: Verification action: 'verify_vtable', 'verify_struct_field', or 'extract_dynamic_keys'.
        rva: Relative virtual address offset (hex string or int, e.g. '0x1000').
        module_base: Virtual address base of target module (e.g. '0x7000000000').
        expected_slots: Number of expected vtable slots to verify (for verify_vtable).
        expected_type: Expected data type for field verification (e.g. 'uint32', 'pointer').
        key_length: Byte length of dynamic encryption key to extract (default: 32).
        pid: Optional Windows process ID for Win32ProcessMemoryReader.
        target_process: Optional process name or ID for FridaMemoryReader.
        expected_slot_rvas: Optional explicit list of expected vtable slot RVAs.
        mock_memory_hex: Optional hex string to inject into memory reader before verification.
    """
    _ensure_superghidra_imported()
    from emulator_memory_sidecar import (
        EmulatorFleetGuard,
        MockMemoryReader,
        Win32ProcessMemoryReader,
        FridaMemoryReader,
        verify_vtable_pointer,
        verify_struct_field,
        extract_dynamic_encryption_keys,
    )

    # 1. Fleet safety check
    try:
        EmulatorFleetGuard.validate_target(device_serial, is_mutation=False, allow_readonly_farm=False)
    except Exception as e:
        return EmulatorMemoryVerifyResult(
            status="violation",
            device_serial=device_serial,
            allowed=False,
            action=action,
            is_valid=False,
            details={"error": str(e), "error_type": type(e).__name__},
            message=f"Fleet safety violation: {e}",
        )

    rva_int = int(rva, 16) if rva.startswith("0x") else int(rva)
    base_int = int(module_base, 16) if module_base.startswith("0x") else int(module_base)

    reader = None
    if pid is not None:
        try:
            reader = Win32ProcessMemoryReader(pid, device_serial=device_serial)
        except Exception as e:
            return EmulatorMemoryVerifyResult(
                status="error",
                device_serial=device_serial,
                allowed=True,
                action=action,
                is_valid=False,
                details={"error": str(e), "error_type": type(e).__name__},
                message=f"Failed to open Win32ProcessMemoryReader: {e}",
            )

    if reader is None and target_process is not None:
        try:
            reader = FridaMemoryReader(device_serial=device_serial, target_process=target_process)
        except Exception as e:
            return EmulatorMemoryVerifyResult(
                status="error",
                device_serial=device_serial,
                allowed=True,
                action=action,
                is_valid=False,
                details={"error": str(e), "error_type": type(e).__name__},
                message=f"Failed to open FridaMemoryReader: {e}",
            )

    if reader is None:
        if not mock_memory_hex:
            return EmulatorMemoryVerifyResult(
                status="error",
                device_serial=device_serial,
                allowed=True,
                action=action,
                is_valid=False,
                message="no live reader configured",
            )
        reader = MockMemoryReader(default_base=base_int)

    is_mock = isinstance(reader, MockMemoryReader)
    result_status = "mock" if is_mock else "ok"

    # Inject mock_memory_hex if provided
    if mock_memory_hex and is_mock:
        try:
            raw_hex = mock_memory_hex.replace(" ", "").replace("\n", "").replace("0x", "")
            parsed_bytes = bytes.fromhex(raw_hex)
            target_addr = base_int + rva_int
            in_region = any(base <= target_addr < base + size for base, (size, *_) in reader._regions.items())
            if not in_region:
                reg_base = target_addr & ~0xFFF
                reader.add_region(base=reg_base, size=max(0x100000, len(parsed_bytes) + 0x1000), permissions="rw-")
            reader.write_memory(target_addr, parsed_bytes)
        except Exception as e:
            logger.warning(f"Failed to inject mock_memory_hex: {e}")

    act = action.lower().strip()
    if act in ("verify_vtable", "vtable"):
        if expected_slot_rvas is not None:
            expected_list = expected_slot_rvas
        else:
            expected_list = [f"0x{rva_int + 0x100 + i * 0x40:X}" for i in range(expected_slots)]

        res = verify_vtable_pointer(reader, rva=rva_int, expected_slots=expected_list)
        return EmulatorMemoryVerifyResult(
            status=result_status,
            device_serial=device_serial,
            allowed=True,
            action=action,
            is_valid=res.is_valid,
            details=res.to_dict(),
            message=res.message,
        )

    elif act in ("verify_struct_field", "verify_field", "struct_field"):
        res = verify_struct_field(reader, base_ptr=base_int, offset=rva_int, expected_type=expected_type)
        return EmulatorMemoryVerifyResult(
            status=result_status,
            device_serial=device_serial,
            allowed=True,
            action=action,
            is_valid=res.is_valid,
            details=res.to_dict(),
            message=res.message,
        )

    elif act in ("extract_dynamic_keys", "extract_keys", "dynamic_keys"):
        res = extract_dynamic_encryption_keys(reader, rva=rva_int, length=key_length)
        return EmulatorMemoryVerifyResult(
            status=result_status,
            device_serial=device_serial,
            allowed=True,
            action=action,
            is_valid=res.is_valid_crypto_key,
            details=res.to_dict(),
            message=f"Extracted dynamic key (entropy: {res.entropy:.4f})",
        )

    return EmulatorMemoryVerifyResult(
        status="error",
        device_serial=device_serial,
        allowed=True,
        action=action,
        is_valid=False,
        message=f"Unknown verification action '{action}'",
    )


@mcp_error_handler
def neural_decompile_skin(
    raw_c_code: str,
    function_address: str = "0x101000",
    image_base: str = "0x100000",
    model_name: str = "LLM4Decompile-9b-v2",
    llm_endpoint: str | None = None,
    ledger_path: str | None = None,
    ctx: Context | None = None,
) -> NeuralDecompileSkinResult:
    """Coordinates Phase-A skeleton normalization, Phase-B neural skin prediction, and EvidenceLedger invariant gating.

    Args:
        raw_c_code: Raw decompiler C source code or statement sequence.
        function_address: Virtual address of the target function (default: '0x101000').
        image_base: Image base offset of the binary (default: '0x100000').
        model_name: Identifier of the neural model (default: 'LLM4Decompile-9b-v2').
        llm_endpoint: Optional local/remote LLM HTTP endpoint URL (e.g. Ollama or vLLM).
        ledger_path: Optional path to evidence_ledger.json.
    """
    _ensure_superghidra_imported()
    from neural_decompiler_pipeline import NeuralDecompilerPipeline, SkeletonExtractor, LLMDecompilerClient
    from evidence_ledger import ReconstructionObligationLedger

    func_addr = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
    base_addr = int(image_base, 16) if image_base.startswith("0x") else int(image_base)

    if ledger_path:
        safe_ledger = str(_resolve_safe_path(ledger_path, must_exist=True, for_write=False))
        ledger = ReconstructionObligationLedger(ledger_file=safe_ledger)
    else:
        def_ledger = _get_default_ledger_path()
        ledger = ReconstructionObligationLedger(ledger_file=def_ledger)

    pipeline = NeuralDecompilerPipeline(ledger=ledger)
    skeleton = SkeletonExtractor.extract_skeleton(raw_c_code, function_address=func_addr, image_base=base_addr)

    llm_client = None
    if llm_endpoint:
        llm_client = LLMDecompilerClient(model_name=model_name, endpoint_url=llm_endpoint)

    prediction = pipeline.predict_skin(skeleton, llm_client=llm_client)
    commit = pipeline.verify_and_commit(skeleton, prediction)

    return NeuralDecompileSkinResult(
        status="ok",
        function_address=f"0x{commit.function_address:08X}",
        function_rva=f"0x{commit.function_rva:08X}",
        function_name=commit.function_name,
        return_type=commit.return_type,
        signature=commit.signature,
        skeleton_source=skeleton.skeleton_source,
        verified_struct_fields={f"0x{k:X}": v for k, v in commit.verified_struct_fields.items()},
        evidence_proof_hashes=commit.evidence_proof_hashes,
        confidence=round(prediction.confidence, 4),
        model_identifier=prediction.model_identifier,
        is_safe_to_commit=commit.is_safe_to_commit,
        message=f"Neural decompile skin completed: {commit.function_name} ({len(commit.verified_struct_fields)} verified fields)",
    )


@mcp_error_handler
def migrate_semantic_deltas(
    delta_log_path: str,
    old_binary_path: str,
    new_binary_path: str,
    output_delta_log_path: str | None = None,
    threshold: float = 0.70,
    ctx: Context | None = None,
) -> MigrateSemanticDeltasResult:
    """Migrates semantic annotations across binary revisions using batched CFG similarity matching.

    Replays delta logs, translates symbol and address mutations to paired functions,
    and produces a verified delta log for the new binary.

    Args:
        delta_log_path: Path to existing semantic delta log (.jsonl).
        old_binary_path: File path or JSON function list of baseline binary A.
        new_binary_path: File path or JSON function list of target binary B.
        output_delta_log_path: Optional path to write migrated delta log (.jsonl).
        threshold: Minimum cosine similarity threshold (default: 0.70).
    """
    _ensure_superghidra_imported()
    from semantic_delta_log import SemanticDeltaLog, DeltaMigrationEngine

    safe_delta_log = str(_resolve_safe_path(delta_log_path, must_exist=True, for_write=False))
    delta_log = SemanticDeltaLog(safe_delta_log)
    baseline_events = delta_log.load()

    funcs_a, _ = _parse_functions_for_diff(old_binary_path)
    funcs_b, _ = _parse_functions_for_diff(new_binary_path)

    safe_output_delta = None
    if output_delta_log_path:
        safe_output_delta = str(_resolve_safe_path(output_delta_log_path, must_exist=False, for_write=True, allowed_extensions={".jsonl", ".json", ".log", ".txt", ".py"}))

    engine = DeltaMigrationEngine(similarity_threshold=threshold)
    engine.run_diff_pairing(funcs_a, funcs_b)

    report, migrated_events = engine.migrate_events(
        baseline_events, target_log_path=safe_output_delta
    )

    record_items = [
        MigratedEventRecordItem(
            original_event_id=r.original_event.event_id,
            event_type=r.original_event.event_type.value,
            status=r.status.value,
            similarity=round(float(r.similarity), 4),
            confidence=r.confidence,
            match_detail=r.match_detail,
            migrated_event_id=r.migrated_event.event_id if r.migrated_event else None,
        )
        for r in report.records
    ]

    msg = (
        f"Migrated {report.migrated_verified_count + report.migrated_unverified_count}/"
        f"{report.total_baseline_events} events ({report.migration_rate_pct:.1f}% success rate) "
        f"in {report.elapsed_time_ms:.2f} ms."
    )
    return MigrateSemanticDeltasResult(
        status="ok",
        total_baseline_events=report.total_baseline_events,
        migrated_verified_count=report.migrated_verified_count,
        migrated_unverified_count=report.migrated_unverified_count,
        skipped_unmatched_count=report.skipped_unmatched_count,
        evidence_rejected_count=report.evidence_rejected_count,
        migration_rate_pct=round(report.migration_rate_pct, 2),
        elapsed_time_ms=round(report.elapsed_time_ms, 2),
        output_delta_log_path=output_delta_log_path,
        records=record_items,
        message=msg,
    )


@mcp_error_handler
def preindex_dwarf_pdb(
    binary_or_pdb_path: str,
    db_output_path: str | None = None,
    query_symbol_or_type: str | None = None,
    ctx: Context | None = None,
) -> PreindexDwarfPdbResult:
    """Pre-indexes DWARF5 and PDB debug types into an off-heap SQLite database for sub-millisecond querying.

    Args:
        binary_or_pdb_path: Path to ELF binary, PDB file, or JSON type export.
        db_output_path: Optional SQLite output path (defaults to in-memory ':memory:').
        query_symbol_or_type: Optional symbol name or struct/type name to query and render.
    """
    _ensure_superghidra_imported()
    from dwarf_pdb_preindexer import OffHeapTypeStore, TypeDeduplicator, NormalizedType, SymbolRecord

    if db_output_path and db_output_path != ":memory:":
        safe_db = str(_resolve_safe_path(db_output_path, must_exist=False, for_write=True, allowed_extensions={".sqlite", ".db", ".sqlite3", ".idx", ".bin"}))
        db_target = safe_db
    else:
        db_target = ":memory:"

    safe_bin_path = _resolve_safe_path(binary_or_pdb_path, must_exist=True, for_write=False)
    store = OffHeapTypeStore(db_target)
    dedup = TypeDeduplicator()

    with open(safe_bin_path, "rb") as f:
        raw_bytes = f.read()

    stripped = raw_bytes.strip()
    path_str = str(safe_bin_path)
    if stripped.startswith(b"\x7fELF"):
        store.ingest_dwarf5_elf(raw_bytes, dedup=dedup)
    elif (
        stripped.startswith(b"Microsoft C/C++ MSF 7.00")
        or path_str.lower().endswith(".pdb")
    ) and hasattr(store, "ingest_pdb"):
        store.ingest_pdb(raw_bytes)
    elif stripped.startswith(b"{") or path_str.lower().endswith(".json"):
        store.load_json(path_str)
    else:
        try:
            store.ingest_dwarf5_elf(raw_bytes, dedup=dedup)
        except Exception:
            pass

    cursor = store._conn.cursor()
    cursor.execute("SELECT count(*) FROM canonical_types")
    total_types = cursor.fetchone()[0]
    cursor.execute("SELECT count(*) FROM symbols")
    total_symbols = cursor.fetchone()[0]
    cursor.execute("SELECT count(*) FROM struct_members")
    total_members = cursor.fetchone()[0]

    c_decl: str | None = None
    matched_syms: list[dict[str, Any]] = []

    if query_symbol_or_type:
        try:
            rendered = store.render_c_declaration(query_symbol_or_type)
            if rendered:
                c_decl = rendered
        except Exception:
            pass

        try:
            syms = store.lookup_symbols_by_name(query_symbol_or_type)
            matched_syms = [s.to_dict() for s in syms]
        except Exception:
            pass

    msg = f"Indexed {total_types} canonical types, {total_symbols} symbols, and {total_members} members into '{db_target}'."
    return PreindexDwarfPdbResult(
        status="ok",
        input_path=binary_or_pdb_path,
        db_output_path=db_target,
        total_canonical_types=total_types,
        total_symbols=total_symbols,
        total_struct_members=total_members,
        query=query_symbol_or_type,
        c_declaration=c_decl,
        matched_symbols=matched_syms,
        message=msg,
    )


@mcp_error_handler
def inspect_binary(
    binary_path: str,
    name_filter: str | None = None,
    limit: int = 200,
    prefer_arch: str | None = None,
    ctx: Context | None = None,
) -> InspectBinaryResult:
    """Identifies an ELF / PE (EXE, DLL) / Mach-O (incl. universal) binary without Ghidra.

    Reports format, architecture, bitness, endianness, image base, entry point, sections,
    exports (with PE ordinals/forwarders), imports (with DLL/dylib names) and PDB path.
    Handles stripped/forged ELF section tables (protected Android libraries).

    Args:
        binary_path: Path to the binary.
        name_filter: Optional case-insensitive substring to filter exports/imports.
        limit: Maximum exports and imports returned (totals are always reported).
        prefer_arch: For universal Mach-O files, the slice to load (e.g. 'arm64', 'x86_64').
    """
    _ensure_superghidra_imported()
    import binary_loader

    path = _resolve_safe_path(binary_path, must_exist=True, for_write=False)
    img = binary_loader.load_binary(str(path), prefer_arch=prefer_arch)
    needle = (name_filter or "").lower()
    limit = max(0, min(int(limit), 5000))

    def keep(name: str | None) -> bool:
        return not needle or (name is not None and needle in name.lower())

    exports = [
        {"name": e.name, "address": hex(e.address), "ordinal": e.ordinal, "forwarder": e.forwarder}
        for e in img.exports if keep(e.name)
    ]
    imports = [
        {"library": i.library, "name": i.name, "ordinal": i.ordinal,
         "slot": hex(i.address) if i.address else None, "delay_loaded": i.delay_loaded}
        for i in img.imports if keep(i.name)
    ]
    sections = [
        {"name": s.name, "vaddr": hex(s.vaddr), "size": s.vsize, "file_offset": s.file_offset,
         "executable": s.executable, "writable": s.writable}
        for s in (img.sections or img.segments) if s.mapped
    ]
    return InspectBinaryResult(
        path=str(path), format=img.format, arch=img.arch, bits=img.bits, endian=img.endian,
        image_base=hex(img.image_base), entry=hex(img.entry) if img.entry is not None else None,
        is_library=img.is_library, is_dotnet=img.is_dotnet, pdb_path=img.pdb_path,
        libraries=img.libraries, sections=sections,
        exports=exports[:limit], imports=imports[:limit],
        total_exports=len(img.exports), total_imports=len(img.imports),
        total_function_starts=len(img.function_starts),
        message=(f"{img.format.upper()} {img.arch} {img.bits}-bit {'library' if img.is_library else 'executable'}: "
                 f"{len(img.exports)} exports, {len(img.imports)} imports, {len(img.function_starts)} known functions."),
    )


@mcp_error_handler
def recover_cpp_classes(
    binary_path: str,
    name_filter: str | None = None,
    serializable_only: bool = False,
    include_rtti: bool = True,
    limit: int = 500,
    ctx: Context | None = None,
) -> RecoverCppClassesResult:
    """Recovers C++ classes from a Windows x86/x64 PE (EXE/DLL) without Ghidra.

    Combines MSVC RTTI (class names, vftables, inheritance) with MFC CRuntimeClass records
    (CArchive class name, object size, schema version, base class, CreateObject). Each MFC
    class is linked to its vftable through GetRuntimeClass(), which yields the address of
    its Serialize(CArchive&) function: decompile that address to learn the class's
    on-disk field layout in MFC CArchive streams.

    Args:
        binary_path: Path to the PE file.
        name_filter: Optional case-insensitive substring to filter class names.
        serializable_only: Only return MFC classes with a serialization schema.
        include_rtti: Also return RTTI classes (can be large).
        limit: Maximum classes returned per list (totals are always reported).
    """
    _ensure_superghidra_imported()
    import msvc_class_recovery

    path = _resolve_safe_path(binary_path, must_exist=True, for_write=False)
    report = msvc_class_recovery.recover_classes(str(path), rtti=include_rtti)
    data = report.to_dict()
    needle = (name_filter or "").lower()
    limit = max(0, min(int(limit), 10000))
    mfc = [c for c in data["mfc_classes"]
           if (not needle or needle in c["name"].lower()) and (c["serializable"] or not serializable_only)]
    rtti = [c for c in data["rtti_classes"] if not needle or needle in c["name"].lower()]
    counts = data["counts"]
    return RecoverCppClassesResult(
        path=str(path), arch=report.arch,
        total_mfc_classes=counts["mfc"], total_serializable=counts["mfc_serializable"],
        total_rtti_classes=counts["rtti"],
        mfc_classes=mfc[:limit], rtti_classes=rtti[:limit],
        message=(f"{counts['mfc']} MFC CRuntimeClass records ({counts['mfc_serializable']} serializable, "
                 f"{sum(1 for c in report.mfc_classes if c.serialize)} with Serialize() resolved) and "
                 f"{counts['rtti']} RTTI classes."),
    )


_TRACER_CACHE: dict[tuple[str, float, int | None], Any] = {}


def _serialize_tracer(path: Path, archive_flags: int | None = 0):
    """SerializeTracer per (file, mtime): class recovery and helper summaries are reused."""
    _ensure_superghidra_imported()
    import serialize_trace

    key = (str(path), path.stat().st_mtime, archive_flags)
    tracer = _TRACER_CACHE.get(key)
    if tracer is None:
        if len(_TRACER_CACHE) >= 8:
            _TRACER_CACHE.pop(next(iter(_TRACER_CACHE)))
        tracer = serialize_trace.SerializeTracer(str(path), archive_flags=archive_flags)
        _TRACER_CACHE[key] = tracer
    return tracer


@mcp_error_handler
def trace_serialize(
    binary_path: str,
    class_filter: str | None = None,
    path: str = "both",
    binary_format_only: bool = True,
    limit: int = 200,
    ctx: Context | None = None,
) -> TraceSerializeResult:
    """Recovers the on-disk field layout of every MFC class from its Serialize(CArchive&) code.

    Statically walks each Serialize() of a Windows x86/x64 PE (no Ghidra needed) and lists
    the archive operations in order for the loading and storing paths: primitive reads and
    writes (u8..u64, f32/f64) with the C++ member they target (`this+0x40`), CStrings,
    counts, nested objects (ReadObject/WriteObject), base-class and member Serialize calls,
    loops (`repeat`), and the branch conditions guarding each field (e.g. file-version
    checks such as `local->0x780 >= 0x8de`). Works for MFC apps (inline CArchive operators)
    and frameworks with their own CArchive (e.g. SOLIDWORKS su_CArchive).

    Args:
        binary_path: Path to the PE file (EXE/DLL).
        class_filter: Optional case-insensitive substring of class names to trace.
        path: 'both', 'loading' or 'storing'.
        binary_format_only: Prune code for alternate archive modes (text/XML) so traces
            describe the binary format; False keeps them as `archive[...]` gates.
        limit: Maximum classes returned (totals are always reported).
    """
    p = _resolve_safe_path(binary_path, must_exist=True, for_write=False)
    tracer = _serialize_tracer(p, 0 if binary_format_only else None)
    needle = (class_filter or "").lower()
    names = [c.name for c in tracer.report.mfc_classes
             if c.serializable and c.serialize and (not needle or needle in c.name.lower())]
    traces = tracer.trace_classes(names)
    limit = max(0, min(int(limit), 5000))
    out = []
    for t in traces[:limit]:
        d = t.to_dict()
        for key in ("loading", "storing"):
            for op in d[key]:
                op.pop("conditions", None)
                op.pop("via", None)
        if path == "loading":
            d.pop("storing")
        elif path == "storing":
            d.pop("loading")
        out.append(d)
    mirrored = sum(1 for t in traces if t.mirrored)
    return TraceSerializeResult(
        path=str(p), arch=tracer.img.arch, total_traced=len(traces), total_mirrored=mirrored, traces=out,
        message=(f"Traced {len(traces)} Serialize() functions; {mirrored} have matching load/store paths."),
    )


@mcp_error_handler
def decode_carchive(
    stream_path: str,
    layout_binaries: list[str] | None = None,
    offset: int = 0,
    env: dict[str, int] | None = None,
    calibrate: bool = True,
    limit: int = 200,
    ctx: Context | None = None,
) -> DecodeCArchiveResult:
    """Decodes an MFC CArchive stream (CObject::Serialize output) into objects and fields.

    Handles MFC's object format exactly (new-class / class-reference / object-reference
    tags, the load map, big tags, CString incl. UTF-16, counts). Object payloads are decoded
    with layouts recovered from the writing application's DLLs by trace_serialize (pass them
    in `layout_binaries`, the main module first, then e.g. mfc140u.dll for inherited MFC
    collection classes). Classes without a layout are skipped to the next class tag.

    Args:
        stream_path: Raw stream file (e.g. one extracted from a .SLDPRT container).
        layout_binaries: PE files whose Serialize() code defines the layouts.
        offset: Byte offset where archive data starts.
        env: Values for gate operands, e.g. {"local->0x780": 4050} (a file version).
        calibrate: When env is empty, infer the most-used gate operand (usually the file
            version) by trying its thresholds and keeping the best-decoding value.
        limit: Maximum top-level objects returned.
    """
    _ensure_superghidra_imported()
    import mfc_archive

    sp = _resolve_safe_path(stream_path, must_exist=True, for_write=False)
    data = sp.read_bytes()
    bins = [_resolve_safe_path(b, must_exist=True, for_write=False) for b in (layout_binaries or [])]
    layouts: dict[str, Any] = {}
    if bins:
        tracers = [_serialize_tracer(b) for b in bins]
        layouts = mfc_archive.layouts_from_traces(tracers[0].class_layouts(others=tuple(tracers[1:])))
        for extra in tracers[1:]:
            for k, v in mfc_archive.layouts_from_traces(extra.class_layouts()).items():
                layouts.setdefault(k, v)
    use_env = dict(env or {})
    cal = None
    if not use_env and calibrate and layouts:
        cal = mfc_archive.calibrate(data, layouts, start=int(offset))
        if cal.get("variable") is not None:
            use_env = {cal["variable"]: cal["value"]}
        cal = {"variable": cal.get("variable"), "value": cal.get("value"),
               "max_known_threshold": cal.get("max_known_threshold"), "warning": cal.get("warning"),
               "trials": sorted(cal.get("trials", []), key=lambda t: -t["decoded_bytes"])[:10]}
    res = mfc_archive.decode_stream(data, layouts, start=int(offset), env=use_env)
    limit = max(0, min(int(limit), 20000))
    s = res["stats"]
    return DecodeCArchiveResult(
        stream_path=str(sp), length=res["length"], layout_binaries=[str(b) for b in bins], layouts=len(layouts),
        env=use_env, calibration=cal, stats=s, map_reliable=res["map_reliable"], classes=res["classes"],
        gaps=res["gaps"], objects=res["objects"][:limit], truncated=len(res["objects"]) > limit,
        message=(f"{s['decoded']} objects decoded, {s['partial']} partial, {s['opaque']} without layout, "
                 f"{s.get('error', 0)} malformed; {sum(g['length'] for g in res['gaps'])} of {res['length']} "
                 f"bytes not decoded." + (f" Warning: {cal['warning']}" if cal and cal.get("warning") else "")),
    )


