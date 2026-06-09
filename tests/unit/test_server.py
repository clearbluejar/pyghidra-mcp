from pathlib import Path
from unittest.mock import Mock

import click.testing

import pyghidra_mcp.server as server


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
