"""CLI entry point for pyghidra-mcp client.

This CLI connects to a running pyghidra-mcp server and provides a user-friendly
interface for binary analysis.

Usage examples:
    # Connect to HTTP server running on default port
    pyghidra-mcp-cli list binaries

    # Connect to server on custom port
    pyghidra-mcp-cli --port 8080 list binaries

Prerequisites:
    The pyghidra-mcp server must be running. Start it with:

    # Option 1: Open existing project
    pyghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

    # Option 2: Import and analyze a binary
    pyghidra-mcp --transport streamable-http --wait-for-analysis /bin/ls

    # Option 3: Import multiple binaries
    pyghidra-mcp --transport streamable-http --wait-for-analysis /path/to/binary1 /path/to/binary2
"""

import click

from . import __version__
from .commands import callgraph, decompile, delete, import_cmd, metadata, read, search, xref
from .commands import list as list_mod

SERVER_NOT_RUNNING_ERROR = """Error: Cannot connect to pyghidra-mcp server.

The CLI requires a running pyghidra-mcp server. Please start it first:

Examples:

1. Open existing Ghidra project:
   pyghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

2. Import and analyze a binary:
   pyghidra-mcp --transport streamable-http --wait-for-analysis /bin/ls

3. Import multiple binaries:
   pyghidra-mcp --transport streamable-http --wait-for-analysis ./binary1 ./binary2

After starting the server, run this CLI again:
   pyghidra-mcp-cli list binaries
"""


@click.group()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Server host address.",
)
@click.option(
    "--port",
    type=int,
    default=8000,
    show_default=True,
    help="Server port.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose output.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "table", "text"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.version_option(version=__version__, prog_name="pyghidra-mcp-cli")
@click.pass_context
def cli(
    ctx: click.Context,
    host: str,
    port: int,
    verbose: bool,
    output_format: str,
) -> None:
    """PyGhidra MCP Command-Line Client

    A CLI tool to interact with pyghidra-mcp server for binary analysis.

    This client connects to an existing pyghidra-mcp server via HTTP.
    The server must be started separately before using this CLI.

    Quick start:
        # 1. Start the server (in another terminal)
        pyghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

        # 2. Use the CLI
        pyghidra-mcp-cli list binaries

    Examples:
        # List available binaries
        pyghidra-mcp-cli list binaries

        # Decompile a function
        pyghidra-mcp-cli decompile --binary myapp main

        # Search for symbols
        pyghidra-mcp-cli search symbols --binary myapp malloc -l 20

        # Search for code patterns
        pyghidra-mcp-cli search code --binary myapp "AES key schedule" -l 5

        # List imports
        pyghidra-mcp-cli list imports --binary myapp

        # Generate call graph
        pyghidra-mcp-cli callgraph --binary myapp main

        # Read bytes at address
        pyghidra-mcp-cli read --binary myapp 0x1000 -s 64

        # Show cross-references
        pyghidra-mcp-cli xref --binary myapp 0x401000

        # Import a binary
        pyghidra-mcp-cli import /path/to/binary

        # Delete a binary
        pyghidra-mcp-cli delete --binary myapp

        # Show binary metadata
        pyghidra-mcp-cli metadata --binary myapp
    """
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["PORT"] = port
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["OUTPUT_FORMAT"] = output_format


# Register commands
cli.add_command(decompile.decompile)
cli.add_command(search.search)
cli.add_command(list_mod.list_cmd)
cli.add_command(xref.xref)
cli.add_command(read.read)
cli.add_command(callgraph.callgraph)
cli.add_command(import_cmd.import_cmd)
cli.add_command(delete.delete)
cli.add_command(metadata.metadata)


if __name__ == "__main__":
    cli()
