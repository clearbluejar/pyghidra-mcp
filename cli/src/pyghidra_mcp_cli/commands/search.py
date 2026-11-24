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
@click.option(
    "-f", "--functions-only", is_flag=True, default=False, help="Search only function symbols."
)
@click.pass_context
def symbols(
    ctx: click.Context, binary_name: str, query: str, offset: int, limit: int, functions_only: bool
) -> None:
    """Search for symbols by name in a binary."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.search_symbols(
                binary_name, query, functions_only=functions_only, offset=offset, limit=limit
            )
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


@search.command(name="bytes")
@binary_option
@click.argument("pattern", required=False)
@click.option("--value", help="Unsigned value to find (decimal or 0x hex) instead of a pattern.")
@click.option("--width", type=int, default=4, help="Value width in bytes: 1, 2, 4, or 8.")
@click.option(
    "--endian",
    type=click.Choice(["little", "big"]),
    default="little",
    help="Value byte order.",
)
@click.option("--thumb", is_flag=True, help="Also match the value with its low bit set.")
@click.option("--start", help="Inclusive start address (hex).")
@click.option("--end", help="Inclusive end address (hex).")
@click.option("--alignment", type=int, default=1, help="Match alignment: 1, 2, 4, or 8.")
@click.option("-l", "--limit", type=int, default=50, help="Maximum results to return (1-1000).")
@click.option("--context", type=int, default=0, help="Bytes of context each side (0-16).")
@click.pass_context
def bytes(
    ctx: click.Context,
    binary_name: str,
    pattern: str | None,
    value: str | None,
    width: int,
    endian: str,
    thumb: bool,
    start: str | None,
    end: str | None,
    alignment: int,
    limit: int,
    context: int,
) -> None:
    """Search initialized memory for PATTERN (hex, ?? wildcard) or --value."""

    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.search_bytes(
                binary_name=binary_name,
                pattern=pattern,
                value=value,
                start=start,
                end=end,
                width=width,
                endian=endian,
                thumb=thumb,
                alignment=alignment,
                max_results=limit,
                context_bytes=context,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    import asyncio

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
