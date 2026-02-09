"""Utility functions for pyghidra-mcp CLI."""

import asyncio
import io
import sys
from typing import Any

import click


def get_server_start_message() -> str:
    """Return the standardized server start message."""
    return (
        "Please start the server first!\n\n"
        "Start the server with and existing Ghidra project:\n\n"
        "  pyghidra-mcp -t http --project-path /path/to/project.gpr\n\n"
        "Or start a new Ghidra project and import a new binary:\n\n"
        "  pyghidra-mcp -t http --wait-for-analysis /bin/ls"
    )


def handle_noisy_mcp_errors(error_msg: str) -> bool:
    """
    Check if error_msg contains noisy MCP library patterns and handle them.

    Returns True if the error was handled (was noisy), False if it should be processed further.
    """
    # Patterns that indicate noisy MCP async generator cleanup errors
    noisy_patterns = [
        "async_generator",
        "GeneratorExit",
        "aclose()",
        "unhandled errors in a TaskGroup",
        "Attempted to exit cancel scope",
        "asynchronous generator is already running",
        "Exception Group",
        "CancelledError: Cancelled by cancel scope",
        "anyio.WouldBlock",
    ]

    if not any(pattern in error_msg for pattern in noisy_patterns):
        return False

    # This is noise from the MCP async generator cleanup
    # Check if there's a real error message in there
    if "ServerNotRunningError" in error_msg:
        # Extract and display the real error
        lines = error_msg.split("\n")
        for line in lines:
            line = line.strip()
            if "Cannot connect" in line or "pyghidra-mcp server" in line:
                click.echo(f"Error: {line}", err=True)
                return True

    # If we see connection-related patterns in the noisy error, show connection message
    if any(
        pattern in error_msg.lower() for pattern in ["connection", "connect", "refused", "failed"]
    ):
        show_connection_error()
        return True

    click.echo(
        "Error: An error occurred. Please ensure the pyghidra-mcp server is running.",
        err=True,
    )
    return True


def show_connection_error() -> None:
    """Display a standardized connection error message."""
    click.echo(
        f"Error: Cannot connect to pyghidra-mcp server.\n\n{get_server_start_message()}",
        err=True,
    )


def get_client(ctx: click.Context):
    """Create and return a client with context settings."""
    from .client import PyGhidraMcpClient

    return PyGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )


def run_async(coro):
    """Run an async coroutine with proper cleanup to suppress noisy MCP errors."""

    class QuietRunner:
        def run(self, coro):
            # Suppress stderr during async execution to hide MCP library noise
            old_stderr = sys.stderr

            try:
                sys.stderr = io.StringIO()
                return asyncio.run(coro)
            finally:
                sys.stderr = old_stderr

    return QuietRunner().run(coro)


def handle_command_error(
    error: Exception | asyncio.exceptions.CancelledError, ctx: click.Context | None = None
) -> None:
    """Handle errors from CLI commands and display user-friendly messages."""
    error_msg = str(error)

    # Check for connection-related errors first
    if (
        isinstance(error, (ConnectionRefusedError, ConnectionError, OSError))
        or "ConnectError" in error_msg
        or "connection refused" in error_msg.lower()
        or "all connection attempts failed" in error_msg.lower()
    ):
        show_connection_error()
        return

    # Check for cancellation errors which usually mean connection problems
    if isinstance(error, asyncio.exceptions.CancelledError):
        show_connection_error()
        return

    # Check for noisy async generator/TaskGroup errors from MCP library
    if handle_noisy_mcp_errors(error_msg):
        return

    # Check if this is a binary not found error with available binaries
    if "not found" in error_msg.lower():
        import ast
        import re

        # Look for pattern like ['binary1', 'binary2', ...]
        binaries_match = re.search(r"\[[^\]]*\]", error_msg)

        if binaries_match:
            binaries_str = binaries_match.group()
            try:
                # Try to parse as Python list
                binaries = ast.literal_eval(binaries_str)
                if isinstance(binaries, list) and binaries:
                    click.echo("Error: Binary not found.", err=True)
                    click.echo("\nAvailable binaries:", err=True)
                    for name in binaries[:10]:
                        click.echo(f"  - {name}", err=True)
                    if len(binaries) > 10:
                        click.echo(f"  ... and {len(binaries) - 10} more", err=True)
                    return
            except (ValueError, SyntaxError):
                pass

        # If we can't extract from error message, show the message
        click.echo(f"Error: {error_msg}", err=True)

    elif error.__class__.__name__ == "BinaryNotFoundError":
        click.echo(f"Error: {error}", err=True)

        # Always try to show available binaries for BinaryNotFoundError
        if ctx:
            click.echo("\nAvailable binaries:", err=True)
            try:
                from .client import PyGhidraMcpClient

                client = PyGhidraMcpClient(
                    host=ctx.obj.get("HOST", "127.0.0.1"),
                    port=ctx.obj.get("PORT", 8000),
                )

                async def show_binaries():
                    async with client:
                        result = await client.list_project_binaries()
                        programs = result.get("programs", [])
                        if programs:
                            for prog in programs:
                                name = prog.get("name", "unknown")
                                click.echo(f"  - {name}", err=True)
                        else:
                            click.echo("  No binaries found in project.", err=True)

                run_async(show_binaries())
            except Exception:
                click.echo("  (Could not fetch binary list)", err=True)

    elif error.__class__.__name__ == "ClientError":
        click.echo(f"Error: {error}", err=True)
    else:
        click.echo(f"Error: {error_msg}", err=True)


def format_output(data: Any, fmt: str, verbose: bool = False) -> None:
    """Format and print output based on format option."""
    import json as json_module

    if fmt == "json":
        click.echo(json_module.dumps(data, indent=2))
    elif fmt == "text":
        if isinstance(data, dict):
            for key, value in data.items():
                click.echo(f"{key}: {value}")
        elif isinstance(data, list):
            for item in data:
                click.echo(f"- {item}")
        else:
            click.echo(str(data))
    elif fmt == "table":
        if isinstance(data, list) and data:
            if isinstance(data[0], dict):
                headers = list(data[0].keys())
                click.echo(" | ".join(headers))
                click.echo("-" * (len(headers) * 10))
                for item in data:
                    row = [str(item.get(h, "")) for h in headers]
                    click.echo(" | ".join(row))
        else:
            click.echo(str(data))
