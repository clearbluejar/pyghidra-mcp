from pathlib import Path
from unittest.mock import Mock

import pyghidra_mcp.server as server


def _common_kwargs():
    return {
        "mcp": Mock(),
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
