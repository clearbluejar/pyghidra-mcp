"""List commands for pyghidra-mcp CLI."""

import asyncio

import click

from ..client import PyGhidraMcpClient
from ..utils import format_output, handle_command_error


def binary_option(func):
    """Common --binary option for commands that target a specific binary."""
    return click.option(
        "-b",
        "--binary",
        "binary_name",
        required=True,
        help="Binary name in the project (use 'list binaries' to see available binaries).",
    )(func)


@click.group()
def list_cmd() -> None:
    """List binaries, functions, imports, exports."""
    pass


@list_cmd.command(name="binaries")
@click.pass_context
def list_binaries(ctx: click.Context) -> None:
    """List all binaries in the project."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.list_project_binaries()
            programs = result.get("programs", [])
            if programs:
                click.echo("Available binaries:")
                for prog in programs:
                    name = prog.get("name", "unknown")
                    click.echo(f"  - {name}")
            else:
                click.echo("No binaries found in project.")

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@list_cmd.command(name="imports")
@binary_option
@click.option("-q", "--query", default=".*", help="Filter imports by regex pattern (default: .*).")
@click.option("-o", "--offset", type=int, default=0, help="Offset for pagination.")
@click.option("-l", "--limit", type=int, default=25, help="Maximum results to return.")
@click.pass_context
def list_imports(ctx: click.Context, binary_name: str, query: str, offset: int, limit: int) -> None:
    """List imported functions in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.list_imports(binary_name, query=query, offset=offset, limit=limit)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@list_cmd.command(name="exports")
@binary_option
@click.option("-q", "--query", default=".*", help="Filter exports by regex pattern (default: .*).")
@click.option("-o", "--offset", type=int, default=0, help="Offset for pagination.")
@click.option("-l", "--limit", type=int, default=25, help="Maximum results to return.")
@click.pass_context
def list_exports(ctx: click.Context, binary_name: str, query: str, offset: int, limit: int) -> None:
    """List exported functions in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.list_exports(binary_name, query=query, offset=offset, limit=limit)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
