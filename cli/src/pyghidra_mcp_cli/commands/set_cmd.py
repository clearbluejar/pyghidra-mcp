"""Set commands for pyghidra-mcp CLI."""

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


@click.group(name="set")
def set_cmd() -> None:
    """Set types, comments, and GUI state."""
    pass


@set_cmd.command(name="variable-type")
@binary_option
@click.argument("function_name_or_address")
@click.argument("variable_name")
@click.argument("type_name")
@click.pass_context
def set_variable_type(
    ctx: click.Context,
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    type_name: str,
) -> None:
    """Set a parameter or local type by exact name."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.set_variable_type(
                binary_name,
                function_name_or_address,
                variable_name,
                type_name,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@set_cmd.command(name="function-prototype")
@binary_option
@click.argument("function_name_or_address")
@click.argument("prototype")
@click.pass_context
def set_function_prototype(
    ctx: click.Context,
    binary_name: str,
    function_name_or_address: str,
    prototype: str,
) -> None:
    """Set a function prototype."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.set_function_prototype(
                binary_name,
                function_name_or_address,
                prototype,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@set_cmd.command(name="comment")
@binary_option
@click.argument("target")
@click.argument("comment")
@click.option(
    "-t",
    "--type",
    "comment_type",
    type=click.Choice(
        ["decompiler", "plate", "pre", "eol", "post", "repeatable"], case_sensitive=False
    ),
    default="decompiler",
    show_default=True,
    help="Comment type.",
)
@click.pass_context
def set_comment(
    ctx: click.Context,
    binary_name: str,
    target: str,
    comment: str,
    comment_type: str,
) -> None:
    """Set a decompiler or listing comment."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.set_comment(binary_name, target, comment, comment_type)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@set_cmd.command(name="current-program")
@binary_option
@click.pass_context
def set_current_program(ctx: click.Context, binary_name: str) -> None:
    """Set the active Ghidra GUI program."""

    client = PyGhidraMcpClient(host=ctx.obj["HOST"], port=ctx.obj["PORT"])

    async def run():
        async with client:
            result = await client.set_current_program(binary_name)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
