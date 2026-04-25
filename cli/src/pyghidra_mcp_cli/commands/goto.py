"""GUI navigation command for pyghidra-mcp CLI."""

import asyncio

import click

from ..client import PyGhidraMcpClient
from ..utils import format_output, handle_command_error


@click.command()
@click.option(
    "-b",
    "--binary",
    "binary_name",
    required=True,
    help="Binary name in the project (use 'list binaries' to see available binaries).",
)
@click.argument("target")
@click.option(
    "-t",
    "--type",
    "target_type",
    type=click.Choice(["address", "function"], case_sensitive=False),
    required=True,
    help="Target kind.",
)
@click.pass_context
def goto(ctx: click.Context, binary_name: str, target: str, target_type: str) -> None:
    """Navigate the Ghidra GUI to an address or function."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.goto(binary_name, target, target_type)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
