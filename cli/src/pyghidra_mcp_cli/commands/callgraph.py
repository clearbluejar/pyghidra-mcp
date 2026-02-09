"""Call graph commands for pyghidra-mcp CLI."""

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
@click.argument("function_name")
@click.option(
    "-d",
    "--direction",
    type=click.Choice(["calling", "called"], case_sensitive=False),
    default="calling",
    help="Direction of the call graph.",
)
@click.option(
    "-t",
    "--type",
    "display_type",
    type=click.Choice(["flow", "flow_ends"], case_sensitive=False),
    default="flow",
    help="Display type of the graph.",
)
@click.option(
    "--condense-threshold",
    type=int,
    default=50,
    help="Maximum number of edges before graph condensation (default: 50).",
)
@click.option(
    "--top-layers",
    type=int,
    default=3,
    help="Number of top layers to show in condensed graph (default: 3).",
)
@click.option(
    "--bottom-layers",
    type=int,
    default=3,
    help="Number of bottom layers to show in condensed graph (default: 3).",
)
@click.option(
    "--max-run-time",
    type=int,
    default=120,
    help="Maximum run time in seconds (default: 120).",
)
@click.pass_context
def callgraph(
    ctx: click.Context,
    binary_name: str,
    function_name: str,
    direction: str,
    display_type: str,
    condense_threshold: int,
    top_layers: int,
    bottom_layers: int,
    max_run_time: int,
) -> None:
    """Generate a call graph for a function in a binary."""

    async def run():
        client = PyGhidraMcpClient(
            host=ctx.obj["HOST"],
            port=ctx.obj["PORT"],
        )

        async with client:
            result = await client.gen_callgraph(
                binary_name,
                function_name,
                direction=direction,
                display_type=display_type,
                condense_threshold=condense_threshold,
                top_layers=top_layers,
                bottom_layers=bottom_layers,
                max_run_time=max_run_time,
            )
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
