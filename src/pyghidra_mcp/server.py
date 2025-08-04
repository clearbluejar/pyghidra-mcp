from pyghidra_mcp.models import DecompiledFunction, FunctionInfo, FunctionSearchResults, ProgramInfo, ProgramInfos
from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.decompile import setup_decomplier, decompile_func
from pyghidra_mcp.context import PyGhidraContext
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path
import pyghidra
import click
from typing import Any, List
from mcp.server.fastmcp import FastMCP, Context
from mcp.server import Server
import asyncio
from mcp.server.fastmcp.utilities.logging import get_logger


# Server Logging
# ---------------------------------------------------------------------------------

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # Critical for STDIO transport
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)
logger.info("Server initialized")

# Constants
# ---------------------------------------------------------------------------------
PROJECT_NAME = 'pyghidra_mcp'
PROJECT_LOCATION = 'pyghidra_mcp_projects'

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
    """Decompile a specific function and return the psuedo-c code for the function"""

    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.programs.get(binary_name)

    if not program_info:
        raise ValueError(f"Binary {binary_name} not found")

    prog = program_info.program
    decompiler = program_info.decompiler

    fm = prog.getFunctionManager()
    functions = fm.getFunctions(True)

    await ctx.info(f"Analyzing function {name} for {prog.name}")

    for func in functions:
        if name == func.name:
            f_name, code, sig = decompile_func(func, decompiler)
            return DecompiledFunction(name=f_name, code=code, signature=sig)

    raise ValueError(f"Function {name} not found")


@mcp.tool()
def search_functions_by_name(binary_name: str, query: str, ctx: Context, offset: int = 0, limit: int = 100) -> FunctionSearchResults:
    """
    Search for functions whose name contains the given substring.
    """

    from ghidra.program.model.listing import Function

    if not query:
        raise ValueError("Query string is required")

    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_info = pyghidra_context.programs.get(binary_name)

    if not program_info:
        raise ValueError(f"Binary {binary_name} not found")

    prog = program_info.program

    funcs = []

    fm = prog.getFunctionManager()
    functions = fm.getFunctions(True)

    # Search for functions containing the query string
    for func in functions:
        func: "Function"
        if query.lower() in func.name.lower():
            funcs.append(FunctionInfo(name=func.name,
                         entry_point=str(func.getEntryPoint())))

    return FunctionSearchResults(functions=funcs[offset:limit+offset])


@mcp.tool()
def list_project_binaries(ctx: Context) -> List[str]:
    """List all the binaries within the project."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    return list(pyghidra_context.programs.keys())


@mcp.tool()
def list_project_program_info(ctx: Context) -> ProgramInfos:
    """List all the program info within the project."""
    pyghidra_context: PyGhidraContext = ctx.request_context.lifespan_context
    program_infos = []
    for name, pi in pyghidra_context.programs.items():
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


def init_pyghidra_context(mcp: FastMCP, input_paths: List[Path]) -> FastMCP:

    if not input_paths:
        raise ValueError('Missing Input Paths!')

    bin_paths = [Path(p) for p in input_paths]

    logger.info(f"Analyzing {', '.join(map(str, bin_paths))}")
    logger.info(f"Project: {PROJECT_NAME}")
    logger.info(f"Project: Location {PROJECT_LOCATION}")

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    pyghidra_context = PyGhidraContext(PROJECT_NAME, PROJECT_LOCATION)
    logger.info(f"Importing binaries: {PROJECT_LOCATION}")
    pyghidra_context.import_binaries(bin_paths)
    logger.info(f"Analyize project: {pyghidra_context.project}")
    pyghidra_context.analyze_project()

    mcp._pyghidra_context = pyghidra_context

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
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1, required=True)
def main(transport: str, input_paths: List[Path]) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp
    - transport: Supports stdio, streamable-http, and sse transports.
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on port 8000.

    """

    init_pyghidra_context(mcp, input_paths)

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
