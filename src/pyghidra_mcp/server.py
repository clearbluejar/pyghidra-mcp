from pyghidra_mcp.__init__ import __version__
from pyghidra_mcp.decompile import setup_decomplier, decompile_func
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path
import pyghidra
import click
from typing import Any
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

logger = logging.getLogger("pyghidra-mcp")
logger.info("Server initialized")


# # Section to make autocomplete work
# try:
#     import ghidra
#     from ghidra_builtins import *
# except:
#     pass
# ####

# Constants
# ---------------------------------------------------------------------------------
PROJECT_NAME = 'pyghidra_mcp'
PROJECT_LOCATION = 'pyghidra_mcp_projects'

# Init Pyghidra
# ---------------------------------------------------------------------------------

# def make_lifespan(input_path: Path, cache_url: str):
#     @asynccontextmanager
#     async def lifespan(app) -> AsyncIterator[None]:
#         print(f"Connecting to DB at {db_url}")
#         print(f"Connecting to cache at {cache_url}")
#         # Setup logic here
#         yield
#         # Teardown logic here
#         print("Disconnecting from services")
#     return lifespan


@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[dict]:
    """Manage server startup and shutdown lifecycle."""

    if server.settings['input_path'] is None:
        raise 'Missing Input Path!'

    input_path = Path(server.settings['input_path'])

    logger.info(f"Analyzing {input_path}")
    logger.info(f"Project: {PROJECT_NAME}")
    logger.info(f"Project: Location {PROJECT_LOCATION}")

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # Initialize resources on startup
    with pyghidra.open_program(
            input_path,
            project_name=PROJECT_NAME,
            project_location=PROJECT_LOCATION) as flat_api:

        decompiler = setup_decomplier(flat_api.getCurrentProgram())

        try:
            yield {"flat_api": flat_api, "decompiler": decompiler}
        finally:
            # Clean up on shutdown
            pass

mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)

# MCP Tools
# ---------------------------------------------------------------------------------


@mcp.tool()
async def decompile_function(name: str, ctx: Context) -> str:
    """Decompile a specific function and return the psuedo-c code for the function"""

    flat_api = ctx.request_context.lifespan_context["flat_api"]
    decompiler = ctx.request_context.lifespan_context["decompiler"]

    from ghidra.program.model.listing import Program

    # prog = None
    # with flat_api as flat_apt:
    # set correct typing to leverage autocomplete  my_var: "ghidra-type"
    prog: "Program" = flat_api.getCurrentProgram()

    fm = prog.getFunctionManager()
    functions = fm.getFunctions(True)

    await ctx.info(f"Analyzing {prog.name} data points")

    code = None
    for func in functions:
        if name == func.name:
            name, code, sig = decompile_func(func, decompiler)

    return code


def configure_mcp(mcp: FastMCP, input_path: Path) -> FastMCP:

    mcp.settings = dict(mcp.settings) | {'input_path': input_path}

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
@click.argument("input_path", type=click.Path(exists=True))
def main(transport: str, input_path: Path) -> None:
    """Entry point for the MCP server

    input_path: Path to binary to import,analyze,and expose with pyghidra-mcp
    transport:Supports stdio, streamable-http, and sse transports.
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on port 8000.

    """

    configure_mcp(mcp, input_path)

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "streamable-http":
        mcp.run(transport="streamable-http")
    elif transport == "sse":
        mcp.run(transport="sse")

    else:
        raise ValueError(f"Invalid transport: {transport}")


if __name__ == "__main__":
    main()
