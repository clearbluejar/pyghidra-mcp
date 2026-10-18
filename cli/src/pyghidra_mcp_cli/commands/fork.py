"""Fork commands for pyghidra-mcp CLI.

When several servers open the same Ghidra project, the first holds the project
lock and later ones work on forks. These commands run against the primary server
to review and merge the forks' journaled edits.
"""

import asyncio

import click

from ..client import PyGhidraMcpClient
from ..utils import format_output, handle_command_error


def _run(ctx: click.Context, call) -> None:
    client = PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await call(client)
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)


@click.group(name="fork")
def fork() -> None:
    """Review and merge forks of a shared project."""


@fork.command(name="list")
@click.pass_context
def list_forks(ctx: click.Context) -> None:
    """List forks and their pending (unmerged) edits."""
    _run(ctx, lambda client: client.list_forks())


@fork.command(name="merge")
@click.argument("fork_id")
@click.option("--dry-run", is_flag=True, help="Report what would change without applying.")
@click.option(
    "--overwrite",
    is_flag=True,
    help="Apply conflicting edits over changes made on the primary since the fork.",
)
@click.pass_context
def merge(ctx: click.Context, fork_id: str, dry_run: bool, overwrite: bool) -> None:
    """Replay FORK_ID's edits into the primary project."""
    on_conflict = "overwrite" if overwrite else "skip"
    _run(ctx, lambda client: client.merge_fork(fork_id, dry_run, on_conflict))


@fork.command(name="discard")
@click.argument("fork_id")
@click.pass_context
def discard(ctx: click.Context, fork_id: str) -> None:
    """Delete a stopped fork. Its unmerged edits are lost."""
    _run(ctx, lambda client: client.discard_fork(fork_id))
