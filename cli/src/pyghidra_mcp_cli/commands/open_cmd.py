"""Open commands for pyghidra-mcp CLI."""

import asyncio

import click

from ..client import PyGhidraMcpClient
from ..utils import format_output, handle_command_error


@click.group(name="open")
def open_cmd() -> None:
    """Open GUI resources."""
    pass


@open_cmd.command(name="program")
@click.option(
    "-b",
    "--binary",
    "binary_name",
    required=True,
    help="Binary name in the project (use 'list binaries' to see available binaries).",
)
@click.option(
    "--new-window/--reuse-window",
    default=True,
    show_default=True,
    help="Open in a new CodeBrowser window or reuse a visible one.",
)
@click.pass_context
def open_program(ctx: click.Context, binary_name: str, new_window: bool) -> None:
    """Open a binary in the Ghidra GUI CodeBrowser."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.open_program_in_gui(binary_name, new_window=new_window)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
