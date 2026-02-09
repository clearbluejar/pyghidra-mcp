"""Search commands for pyghidra-mcp CLI."""

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
def search() -> None:
    """Search in the binary."""
    pass


@search.command(name="symbols")
@binary_option
@click.argument("query")
@click.option("-o", "--offset", type=int, default=0, help="Offset for pagination.")
@click.option("-l", "--limit", type=int, default=25, help="Maximum results to return.")
@click.pass_context
def symbols(ctx: click.Context, binary_name: str, query: str, offset: int, limit: int) -> None:
    """Search for symbols by name in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.search_symbols(binary_name, query, offset=offset, limit=limit)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    import asyncio

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@search.command(name="code")
@binary_option
@click.argument("query")
@click.option("-l", "--limit", type=int, default=5, help="Maximum results to return.")
@click.option("-o", "--offset", type=int, default=0, help="Offset for pagination.")
@click.option(
    "-m",
    "--mode",
    type=click.Choice(["semantic", "literal"], case_sensitive=False),
    default="semantic",
    help="Search mode.",
)
@click.option(
    "--full-code/--preview",
    is_flag=True,
    default=True,
    help="Include full code or preview only.",
)
@click.option(
    "-p",
    "--preview-length",
    type=int,
    default=500,
    help="Length of preview in characters when using --preview (default: 500).",
)
@click.option(
    "-t",
    "--similarity-threshold",
    type=float,
    default=0.0,
    help="Minimum similarity score (0.0-1.0) for semantic search results (default: 0.0).",
)
@click.pass_context
def code(
    ctx: click.Context,
    binary_name: str,
    query: str,
    limit: int,
    offset: int,
    mode: str,
    full_code: bool,
    preview_length: int,
    similarity_threshold: float,
) -> None:
    """Search for code patterns in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.search_code(
                binary_name,
                query,
                limit=limit,
                offset=offset,
                search_mode=mode,
                include_full_code=full_code,
                preview_length=preview_length,
                similarity_threshold=similarity_threshold,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    import asyncio

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@search.command(name="strings")
@binary_option
@click.argument("query")
@click.option("-l", "--limit", type=int, default=100, help="Maximum results to return.")
@click.pass_context
def strings(ctx: click.Context, binary_name: str, query: str, limit: int) -> None:
    """Search for strings in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.search_strings(binary_name, query, limit=limit)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    import asyncio

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
