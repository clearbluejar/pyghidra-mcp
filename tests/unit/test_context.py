import sys
import types
from unittest.mock import Mock, call

import pyghidra_mcp.context as context_module
from pyghidra_mcp.context import PyGhidraContext


def test_init_project_programs_uses_domain_file_paths(monkeypatch):
    """Existing project programs should reopen via Ghidra domain paths, not pathlib."""
    ghidra_module = types.ModuleType("ghidra")
    program_module = types.ModuleType("ghidra.program")
    model_module = types.ModuleType("ghidra.program.model")
    listing_module = types.ModuleType("ghidra.program.model.listing")
    listing_module.Program = object

    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.program", program_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", model_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.listing", listing_module)

    context = PyGhidraContext.__new__(PyGhidraContext)
    context.project = Mock()
    context.programs = {}

    root_parent = Mock()
    root_parent.pathname = "/"

    nested_parent = Mock()
    nested_parent.pathname = "/bin/tools"

    root_domain_file = Mock()
    root_domain_file.pathname = "/ls-aa11bb"
    root_domain_file.getName.return_value = "ls-aa11bb"
    root_domain_file.getParent.return_value = root_parent

    nested_domain_file = Mock()
    nested_domain_file.pathname = "/bin/tools/libfoo-cc22dd"
    nested_domain_file.getName.return_value = "libfoo-cc22dd"
    nested_domain_file.getParent.return_value = nested_parent

    context.list_binary_domain_files = Mock(return_value=[root_domain_file, nested_domain_file])
    context.project.openProgram.side_effect = ["root-program", "nested-program"]
    context._init_program_info = Mock(side_effect=["root-info", "nested-info"])

    context._init_project_programs()

    context.project.openProgram.assert_has_calls(
        [
            call("/", "ls-aa11bb", False),
            call("/bin/tools", "libfoo-cc22dd", False),
        ]
    )
    assert context.programs == {
        "/ls-aa11bb": "root-info",
        "/bin/tools/libfoo-cc22dd": "nested-info",
    }


def test_list_program_infos_returns_loaded_programs():
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {
        "/one": "one-info",
        "/two": "two-info",
    }

    assert context.list_program_infos() == ["one-info", "two-info"]


def test_get_program_info_schedules_indexing_for_ready_binary():
    context = PyGhidraContext.__new__(PyGhidraContext)
    program_info = Mock()
    program_info.analysis_complete = True
    context.programs = {"/bin/sample": program_info}
    context.schedule_indexing = Mock()

    result = context.get_program_info("/bin/sample")

    assert result is program_info
    context.schedule_indexing.assert_called_once_with("/bin/sample")


def test_schedule_startup_indexing_skips_large_projects():
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.programs = {f"/bin/{i}": Mock(analysis_complete=True) for i in range(11)}
    context.schedule_indexing = Mock()

    context.schedule_startup_indexing(max_binaries=10)

    context.schedule_indexing.assert_not_called()


def test_schedule_startup_indexing_indexes_small_projects():
    context = PyGhidraContext.__new__(PyGhidraContext)
    program_a = Mock()
    program_a.name = "/bin/a"
    program_a.analysis_complete = True
    program_b = Mock()
    program_b.name = "/bin/b"
    program_b.analysis_complete = True
    context.programs = {"/bin/a": program_a, "/bin/b": program_b}
    context.schedule_indexing = Mock()

    context.schedule_startup_indexing(max_binaries=10)

    context.schedule_indexing.assert_has_calls([call("/bin/a"), call("/bin/b")])


def test_is_binary_file_uses_ghidra_importability(monkeypatch, tmp_path):
    context = PyGhidraContext.__new__(PyGhidraContext)
    candidate = tmp_path / "sample.bin"
    candidate.write_bytes(b"data")
    checked: list = []

    def fake_is_ghidra_importable(path):
        checked.append(path)
        return True

    monkeypatch.setattr(context_module, "is_ghidra_importable", fake_is_ghidra_importable)

    assert context._is_binary_file(candidate) is True
    assert checked == [candidate]


def test_analysis_done_callback_skips_startup_indexing_when_waiting():
    context = PyGhidraContext.__new__(PyGhidraContext)
    context.wait_for_analysis = True
    context.programs = {"/bin/sample": Mock()}
    context.schedule_startup_indexing = Mock()

    future = Mock()
    future.result.return_value = None

    context._analysis_done_callback(future)

    context.schedule_startup_indexing.assert_not_called()
