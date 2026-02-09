"""Delete binary commands for pyghidra-mcp CLI."""

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


@click.command()
@binary_option
@click.pass_context
def delete(ctx: click.Context, binary_name: str) -> None:
    """Delete a binary from the project."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.delete_binary(binary_name)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
