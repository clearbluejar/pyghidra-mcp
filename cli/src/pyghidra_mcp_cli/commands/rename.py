"""Rename commands for pyghidra-mcp CLI."""

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
def rename() -> None:
    """Rename functions and variables."""
    pass


@rename.command(name="function")
@binary_option
@click.argument("function_name_or_address")
@click.argument("new_name")
@click.pass_context
def rename_function(
    ctx: click.Context, binary_name: str, function_name_or_address: str, new_name: str
) -> None:
    """Rename a function."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.rename_function(binary_name, function_name_or_address, new_name)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@rename.command(name="variable")
@binary_option
@click.argument("function_name_or_address")
@click.argument("variable_name")
@click.argument("new_name")
@click.pass_context
def rename_variable(
    ctx: click.Context,
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    new_name: str,
) -> None:
    """Rename a parameter or local by exact name."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.rename_variable(
                binary_name,
                function_name_or_address,
                variable_name,
                new_name,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
