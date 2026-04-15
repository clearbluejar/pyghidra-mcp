"""Decompile commands for pyghidra-mcp CLI."""

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
@click.argument("function_name_or_address")
@click.option("--callees", is_flag=True, help="Include callee function names in the response.")
@click.option("--strings", is_flag=True, help="Include referenced string literals in the response.")
@click.option("--xrefs", is_flag=True, help="Include cross-references to this function.")
@click.pass_context
def decompile(
    ctx: click.Context,
    binary_name: str,
    function_name_or_address: str,
    callees: bool,
    strings: bool,
    xrefs: bool,
) -> None:
    """Decompile a function in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.decompile_function(
                binary_name,
                function_name_or_address,
                include_callees=callees,
                include_strings=strings,
                include_xrefs=xrefs,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
