import json
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import Mock

import click.testing
import pytest
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.server.mcpserver import MCPServer

import pyghidra_mcp.server as server


def test_server_uses_mcp_v2_api():
    assert isinstance(server.mcp, MCPServer)


@pytest.mark.asyncio
async def test_common_tools_register_with_mcp_v2():
    mcp = MCPServer("pyghidra-mcp-test")
    server.register_common_tools(mcp)

    tools = await mcp.list_tools()
    assert {tool.name for tool in tools} == {
        "decompile_function",
        "delete_project_binary",
        "disassemble",
        "gen_callgraph",
        "import_binary",
        "list_exports",
        "list_imports",
        "list_project_binaries",
        "list_project_binary_metadata",
        "list_xrefs",
        "read_bytes",
        "rename_function",
        "rename_variable",
        "save",
        "search_code",
        "search_strings",
        "search_symbols_by_name",
        "set_comment",
        "set_function_prototype",
        "set_variable_type",
    }


@pytest.mark.asyncio
async def test_common_tools_list_over_mcp_v2_protocol():
    mcp = MCPServer("pyghidra-mcp-test")
    server.register_common_tools(mcp)

    async with InMemoryTransport(mcp) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

    assert any(tool.name == "decompile_function" for tool in tools.tools)
    assert any(tool.name == "list_project_binaries" for tool in tools.tools)


@pytest.mark.asyncio
async def test_common_tool_call_over_mcp_v2_protocol():
    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = []

    @asynccontextmanager
    async def lifespan(_mcp):
        yield pyghidra_context

    mcp = MCPServer("pyghidra-mcp-test", lifespan=lifespan)
    server.register_common_tools(mcp)

    async with InMemoryTransport(mcp) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("list_project_binaries")

    assert result.is_error is False
    assert json.loads(result.content[0].text) == {"programs": []}
    pyghidra_context.list_project_binary_infos.assert_called_once_with()


@pytest.mark.asyncio
async def test_tool_validation_failure_is_a_tool_result_error():
    mcp = MCPServer("pyghidra-mcp-test")
    server.register_common_tools(mcp)

    async with InMemoryTransport(mcp) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "disassemble",
                {"binary_name": "sample", "address": "1000", "count": 201},
            )

    assert result.is_error is True
    assert "count must be <= 200" in result.content[0].text


@pytest.mark.parametrize(
    ("transport", "expected_kwargs"),
    [
        ("stdio", {"transport": "stdio"}),
        ("http", {"transport": "streamable-http", "host": "0.0.0.0", "port": 9000}),
        (
            "streamable-http",
            {"transport": "streamable-http", "host": "0.0.0.0", "port": 9000},
        ),
    ],
)
def test_run_mcp_server_dispatches_supported_transports(transport, expected_kwargs):
    mcp = Mock()

    server.run_mcp_server(mcp, transport, host="0.0.0.0", port=9000)

    mcp.run.assert_called_once_with(**expected_kwargs)


def test_run_mcp_server_dispatches_sse_with_deprecation_warning():
    mcp = Mock()

    with pytest.warns(DeprecationWarning, match="SSE transport is deprecated"):
        server.run_mcp_server(mcp, "sse", host="0.0.0.0", port=9000)

    mcp.run.assert_called_once_with(transport="sse", host="0.0.0.0", port=9000)


def test_run_mcp_server_rejects_invalid_transport():
    mcp = Mock()

    with pytest.raises(ValueError, match="Invalid transport: websocket"):
        server.run_mcp_server(mcp, "websocket", host="0.0.0.0", port=9000)

    mcp.run.assert_not_called()


def _common_kwargs():
    return {
        "mcp": Mock(),
        "transport": "stdio",
        "project_name": "proj",
        "project_directory": "/tmp/proj",
        "pyghidra_mcp_dir": Path("/tmp/proj-pyghidra-mcp"),
        "force_analysis": False,
        "verbose_analysis": False,
        "no_symbols": False,
        "gdts": [],
        "program_options_path": None,
        "gzfs_path": None,
        "threaded": True,
        "max_workers": 1,
        "wait_for_analysis": False,
        "list_project_binaries": False,
        "delete_project_binary": None,
        "symbols_path": None,
        "sym_file_path": None,
    }


def test_init_pyghidra_context_skips_full_analysis_for_existing_project(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = []
    fake_context.list_binaries.return_value = ["/bin/existing"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    mcp = server.init_pyghidra_context(
        input_paths=[],
        **_common_kwargs(),
    )

    fake_context.analyze_project.assert_not_called()
    fake_context.schedule_startup_indexing.assert_called_once_with()
    assert mcp._pyghidra_context is fake_context


def test_init_pyghidra_context_analyzes_new_imports(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **_common_kwargs(),
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_called_once_with("/bin/new")
    fake_context.schedule_startup_indexing.assert_not_called()


def test_init_pyghidra_context_wait_for_analysis_skips_background_indexing(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    kwargs = _common_kwargs()
    kwargs["wait_for_analysis"] = True

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **kwargs,
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_not_called()
    fake_context.schedule_startup_indexing.assert_not_called()


def test_init_pyghidra_context_wait_for_analysis_indexes_for_streamable_server(monkeypatch):
    fake_context = Mock()
    fake_context.import_binaries.return_value = ["/bin/new"]
    fake_context.list_binaries.return_value = ["/bin/new"]
    fake_context.programs = {"/bin/new": Mock()}

    monkeypatch.setattr(server, "pyghidra", Mock(start=Mock()))
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=fake_context))

    kwargs = _common_kwargs()
    kwargs["wait_for_analysis"] = True
    kwargs["transport"] = "streamable-http"

    server.init_pyghidra_context(
        input_paths=[Path("/tmp/newbin")],
        **kwargs,
    )

    fake_context.analyze_project.assert_called_once_with()
    fake_context.schedule_indexing.assert_not_called()
    fake_context.schedule_startup_indexing.assert_called_once_with(max_binaries=1)


def test_gui_mode_allows_missing_project_for_auto_create(monkeypatch, tmp_path):
    launcher_state = {}

    class FakeLauncher:
        def __init__(self, gpr_path):
            launcher_state["gpr_path"] = gpr_path

        def start(self):
            launcher_state["started"] = True

        def run_gui_event_loop(self):
            launcher_state["event_loop"] = True

        def request_shutdown(self):
            launcher_state["shutdown"] = True

        def wait_for_shutdown(self):
            return True

    class FakeThread:
        def __init__(self, target, name, daemon):
            self.target = target
            self.name = name
            self.daemon = daemon

        def start(self):
            self.target()

    monkeypatch.setattr(server, "register_gui_tools", Mock())
    monkeypatch.setattr(server, "ensure_macos_framework_python", Mock())
    monkeypatch.setattr(server, "GuiPyGhidraMcpLauncher", FakeLauncher)
    monkeypatch.setattr(server.threading, "Thread", FakeThread)
    monkeypatch.setattr(server, "init_gui_context", Mock())
    monkeypatch.setattr(server, "run_mcp_server", Mock())
    if hasattr(server.mcp, "_pyghidra_context"):
        delattr(server.mcp, "_pyghidra_context")

    runner = click.testing.CliRunner()
    result = runner.invoke(
        server.main,
        [
            "--gui",
            "--transport",
            "http",
            "--project-path",
            str(tmp_path),
            "--project-name",
            "new_project",
        ],
    )

    assert result.exit_code == 0, result.output
    assert launcher_state["gpr_path"] == tmp_path / "new_project.gpr"
    assert launcher_state["started"] is True
    server.init_gui_context.assert_called_once()
