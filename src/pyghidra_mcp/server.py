# Server
# ---------------------------------------------------------------------------------
import json
import logging
import sys
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import click
import pyghidra
from click_option_group import optgroup
from mcp.server import Server
from mcp.server.fastmcp import FastMCP

from pyghidra_mcp import __version__, mcp_tools
from pyghidra_mcp.context import PyGhidraContext
from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.gui_context import GuiPyGhidraContext
from pyghidra_mcp.gui_launcher import GuiPyGhidraMcpLauncher, ensure_macos_framework_python
from pyghidra_mcp.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,  # Critical for STDIO transport
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# Init Pyghidra
# ---------------------------------------------------------------------------------
@asynccontextmanager
async def server_lifespan(server: Server) -> AsyncIterator[MCPContext]:
    """Manage server startup and shutdown lifecycle."""
    try:
        yield server._pyghidra_context  # type: ignore
    finally:
        # pyghidra_context.close()
        pass


mcp = FastMCP("pyghidra-mcp", lifespan=server_lifespan)  # type: ignore


def register_common_tools(server: FastMCP) -> None:
    server.tool()(mcp_tools.decompile_function)
    server.tool()(mcp_tools.search_symbols_by_name)
    server.tool()(mcp_tools.search_code)
    server.tool()(mcp_tools.list_project_binaries)
    server.tool()(mcp_tools.list_project_binary_metadata)
    server.tool()(mcp_tools.rename_function)
    server.tool()(mcp_tools.rename_variable)
    server.tool()(mcp_tools.set_variable_type)
    server.tool()(mcp_tools.set_function_prototype)
    server.tool()(mcp_tools.set_comment)
    server.tool()(mcp_tools.delete_project_binary)
    server.tool()(mcp_tools.list_exports)
    server.tool()(mcp_tools.list_imports)
    server.tool()(mcp_tools.list_xrefs)
    server.tool()(mcp_tools.search_strings)
    server.tool()(mcp_tools.read_bytes)
    server.tool()(mcp_tools.gen_callgraph)
    server.tool()(mcp_tools.import_binary)


def register_gui_tools(server: FastMCP) -> None:
    server.tool()(mcp_tools.list_open_programs)
    server.tool()(mcp_tools.open_program_in_gui)
    server.tool()(mcp_tools.set_current_program)
    server.tool()(mcp_tools.goto)
    server.tool()(mcp_tools.get_gui_context)


register_common_tools(mcp)


def init_pyghidra_context(  # noqa: C901
    mcp: FastMCP,
    *,
    transport: str,
    input_paths: list[Path],
    project_name: str,
    project_directory: str,
    pyghidra_mcp_dir: Path,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdts: list[str],
    program_options_path: str | None,
    gzfs_path: str | None,
    threaded: bool,
    max_workers: int,
    wait_for_analysis: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    symbols_path: str | None,
    sym_file_path: str | None,
) -> FastMCP:
    bin_paths: list[str | Path] = [Path(p) for p in input_paths]
    logger.info(f"Project: {project_name}")
    logger.info(f"Project: Location {project_directory}")

    program_options: dict | None = None
    if program_options_path:
        with open(program_options_path) as f:
            program_options = json.load(f)

    # init pyghidra
    pyghidra.start(False)  # setting Verbose output

    # init PyGhidraContext / import + analyze binaries
    logger.info("Server initializing...")
    pyghidra_context = PyGhidraContext(
        project_name=project_name,
        project_path=project_directory,
        pyghidra_mcp_dir=pyghidra_mcp_dir,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=gdts,
        program_options=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        symbols_path=symbols_path,
        sym_file_path=sym_file_path,
    )

    if list_project_binaries:
        binaries = pyghidra_context.list_binaries()
        if binaries:
            click.echo("Ghidra Project Binaries:")
            for binary_name in binaries:
                click.echo(f"- {binary_name}")
        else:
            click.echo("No binaries found in the project.")
        sys.exit(0)

    if delete_project_binary:
        try:
            if pyghidra_context.delete_program(delete_project_binary):
                click.echo(f"Successfully deleted binary: {delete_project_binary}")
            else:
                click.echo(f"Failed to delete binary: {delete_project_binary}", err=True)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
        sys.exit(0)

    imported_programs: list[str] = []
    if len(bin_paths) > 0:
        logger.info(f"Adding new bins: {', '.join(map(str, bin_paths))}")
        logger.info(f"Importing binaries to {project_directory}")
        imported_programs = pyghidra_context.import_binaries(bin_paths)

    if imported_programs or force_analysis or wait_for_analysis:
        logger.info(f"Analyzing project: {pyghidra_context.project}")
        pyghidra_context.analyze_project()
        if wait_for_analysis:
            if transport != "stdio":
                pyghidra_context.schedule_startup_indexing(
                    max_binaries=max(len(pyghidra_context.programs), 1)
                )
        else:
            for binary_name in imported_programs:
                pyghidra_context.schedule_indexing(binary_name)
    else:
        logger.info("Skipping full-project analysis on startup; using existing project state.")
        pyghidra_context.schedule_startup_indexing()

    if len(pyghidra_context.list_binaries()) == 0:
        logger.warning("No binaries were imported and none exist in the project.")

    mcp._pyghidra_context = pyghidra_context  # type: ignore
    logger.info("Server intialized")

    return mcp


def init_gui_context(
    mcp: FastMCP,
    *,
    project_spec: ProjectSpec,
    input_paths: list[Path],
) -> FastMCP:
    logger.info("Waiting for Ghidra GUI project...")
    gui_context = GuiPyGhidraContext(project_spec=project_spec)
    if input_paths:
        logger.info("Importing/opening GUI binaries: %s", ", ".join(map(str, input_paths)))
        gui_context.import_binaries(input_paths)
    gui_context.schedule_startup_indexing()
    mcp._pyghidra_context = gui_context  # type: ignore
    logger.info("GUI-backed server initialized")
    return mcp


def run_mcp_server(mcp: FastMCP, transport: str) -> None:
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport in ["streamable-http", "http"]:
        mcp.run(transport="streamable-http")
    elif transport == "sse":
        import warnings

        warnings.warn(
            "SSE transport is deprecated per the MCP spec (June 2025). "
            "Use --transport streamable-http instead.",
            DeprecationWarning,
            stacklevel=1,
        )
        mcp.run(transport="sse")
    else:
        raise ValueError(f"Invalid transport: {transport}")


# MCP Server Entry Point
# ---------------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    __version__,
    "-v",
    "--version",
    help="Show version and exit.",
)
# --- Server Options ---
@optgroup.group("Server Options")
@optgroup.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse", "http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    show_default=True,
    help="Transport protocol to use. Note: SSE is deprecated, use streamable-http instead.",
)
@optgroup.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    show_default=True,
    help="Port to listen on for HTTP-based transports.",
)
@optgroup.option(
    "-o",
    "--host",
    type=str,
    default="127.0.0.1",
    envvar="MCP_HOST",
    show_default=True,
    help="Host to listen on for HTTP-based transports.",
)
@optgroup.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("pyghidra_mcp_projects"),
    show_default=True,
    help="Directory path to create new pyghidra-mcp project or an existing Ghidra .gpr file.",
)
@optgroup.option(
    "--project-name",
    type=str,
    default="my_project",
    show_default=True,
    help="Name for the project (used for Ghidra project files). Ignored when using .gpr files.",
)
@optgroup.option(
    "--threaded/--no-threaded",
    default=True,
    show_default=True,
    help="Allow threaded analysis. Disable for debug.",
)
@optgroup.option(
    "--max-workers",
    type=int,
    default=0,  # 0 means multiprocessing.cpu_count()
    show_default=True,
    help="Number of workers for threaded analysis. Defaults to CPU count.",
)
@optgroup.option(
    "--wait-for-analysis/--no-wait-for-analysis",
    default=False,
    show_default=True,
    help="Wait for initial project analysis to complete before starting the server.",
)
@optgroup.option(
    "--gui/--no-gui",
    default=False,
    show_default=True,
    help=(
        "Launch Ghidra GUI in-process, then open the requested project after startup and "
        "serve MCP over HTTP against GUI-open programs. Cannot attach to an already-running "
        "external Ghidra process."
    ),
)
# --- Project Options ---
@optgroup.group("Project Management")
@optgroup.option(
    "--list-project-binaries",
    is_flag=True,
    help="List all ingested binaries in the project.",
)
@optgroup.option(
    "--delete-project-binary",
    type=str,
    help="Delete a specific binary (program) from the project by name.",
)
# --- Analysis Options ---
@optgroup.group("Analysis Options")
@optgroup.option(
    "--force-analysis/--no-force-analysis",
    default=False,
    show_default=True,
    help="Force a new binary analysis each run.",
)
@optgroup.option(
    "--verbose-analysis/--no-verbose-analysis",
    default=False,
    show_default=True,
    help="Verbose logging for analysis step.",
)
@optgroup.option(
    "--no-symbols/--with-symbols",
    default=False,
    show_default=True,
    help="Turn off symbols for analysis.",
)
@optgroup.option(
    "--sym-file-path",
    type=click.Path(exists=True),
    default=None,
    help="Specify single pdb symbol file for bin (default: None)",
)
@optgroup.option(
    "-s",
    "--symbols-path",
    type=click.Path(),
    default=None,
    help="Path for local symbols directory (default: symbols)",
)
@optgroup.option(
    "--gdt",
    type=click.Path(exists=True),
    multiple=True,
    help="Path to GDT files (can be specified multiple times).",
)
@optgroup.option(
    "--program-options",
    type=click.Path(exists=True),
    help="Path to a JSON file containing program options.",
)
@optgroup.option(
    "--gzfs-path",
    type=click.Path(),
    help="Location to store GZFs of analyzed binaries.",
)
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    input_paths: list[Path],
    project_path: Path,
    project_name: str,
    port: int,
    host: str,
    threaded: bool,
    force_analysis: bool,
    verbose_analysis: bool,
    no_symbols: bool,
    gdt: tuple[str, ...],
    program_options: str | None,
    gzfs_path: str | None,
    max_workers: int,
    wait_for_analysis: bool,
    gui: bool,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    sym_file_path: str | None,
    symbols_path: str | None,
) -> None:
    """PyGhidra Command-Line MCP server

    - input_paths: Path to one or more binaries to import, analyze, and expose with pyghidra-mcp\n
    - transport: Supports stdio, streamable-http, and sse transports.\n
    For stdio, it will read from stdin and write to stdout.
    For streamable-http and sse, it will start an HTTP server on the specified port (default 8000).

    """
    try:
        project_spec = ProjectSpec.from_cli(
            project_path,
            project_name,
            default_project_name=DEFAULT_PROJECT_NAME,
        )
    except ValueError as e:
        raise click.BadParameter(str(e)) from e

    project_directory = str(project_spec.project_directory)
    project_name = project_spec.project_name
    pyghidra_mcp_dir = project_spec.pyghidra_mcp_dir
    mcp.settings.port = port
    mcp.settings.host = host

    if gui:
        if transport == "stdio":
            raise click.UsageError("--gui requires --transport streamable-http or --transport http")
        if transport == "sse":
            raise click.UsageError("--gui requires --transport streamable-http or --transport http")
        if list_project_binaries or delete_project_binary:
            raise click.UsageError("GUI mode does not support project-management CLI actions yet")

        register_gui_tools(mcp)
        ensure_macos_framework_python()
        launcher = GuiPyGhidraMcpLauncher(project_spec.gpr_path)
        launcher.start()
        gui_server_error: list[BaseException] = []

        def gui_server_thread() -> None:
            try:
                init_gui_context(mcp=mcp, project_spec=project_spec, input_paths=input_paths)
                run_mcp_server(mcp, transport)
            except BaseException as exc:
                gui_server_error.append(exc)
                logger.exception("GUI MCP server failed during startup or runtime.")
                launcher.request_shutdown()

        server_thread = threading.Thread(
            target=gui_server_thread,
            name="pyghidra-mcp-gui-server",
            daemon=True,
        )
        server_thread.start()
        try:
            launcher.run_gui_event_loop()
        finally:
            launcher.request_shutdown()
            launcher.wait_for_shutdown()
            context = getattr(mcp, "_pyghidra_context", None)
            if context is not None:
                context.close()
        if gui_server_error:
            raise RuntimeError("GUI MCP server failed to start.") from gui_server_error[0]
        return

    init_pyghidra_context(
        mcp=mcp,
        input_paths=input_paths,
        transport=transport,
        project_name=project_name,
        project_directory=project_directory,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=list(gdt),
        program_options_path=program_options,
        gzfs_path=gzfs_path,
        threaded=threaded,
        max_workers=max_workers,
        wait_for_analysis=wait_for_analysis,
        list_project_binaries=list_project_binaries,
        delete_project_binary=delete_project_binary,
        pyghidra_mcp_dir=pyghidra_mcp_dir,
        sym_file_path=sym_file_path,
        symbols_path=symbols_path,
    )

    try:
        run_mcp_server(mcp, transport)
    finally:
        mcp._pyghidra_context.close()  # type: ignore


if __name__ == "__main__":
    main()
