import sys
import threading
from unittest.mock import Mock, call

import pytest

import pyghidra_mcp.gui_context as gui_context_module
from pyghidra_mcp.context import ProgramInfo
from pyghidra_mcp.gui_context import GuiPyGhidraContext


def test_unique_short_name_match_returns_unambiguous_program():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)

    domain_file = Mock()
    domain_file.getName.return_value = "sample"

    program = Mock()
    program.getDomainFile.return_value = domain_file

    program_info = Mock()
    program_info.name = "sample"
    program_info.program = program

    context.programs = {"/folder/sample": program_info}

    assert context._get_unique_short_name_match("sample") is program_info


def test_unique_short_name_match_rejects_ambiguous_programs():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)

    program_infos = []
    for _ in range(2):
        domain_file = Mock()
        domain_file.getName.return_value = "sample"

        program = Mock()
        program.getDomainFile.return_value = domain_file

        program_info = Mock()
        program_info.name = "sample"
        program_info.program = program
        program_infos.append(program_info)

    context.programs = {
        "/one/sample": program_infos[0],
        "/two/sample": program_infos[1],
    }

    with pytest.raises(ValueError, match="ambiguous"):
        context._get_unique_short_name_match("sample")


def test_list_project_binary_infos_includes_closed_domain_files():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.programs = {}
    context._programs_lock = threading.RLock()
    context.refresh_programs = Mock()

    domain_file = Mock()
    domain_file.getPathname.return_value = "/folder/sample"
    domain_file.getMetadata.return_value = {
        "Executable Location": "/bin/sample",
        "Analyzed": "true",
    }
    context.list_binary_domain_files = Mock(return_value=[domain_file])

    infos = context.list_project_binary_infos()

    assert len(infos) == 1
    assert infos[0].name == "/folder/sample"
    assert infos[0].file_path == "/bin/sample"
    assert infos[0].analysis_complete is True
    assert infos[0].metadata["Analyzed"] == "true"
    assert infos[0].code_indexed is False
    assert infos[0].strings_indexed is False


def test_refresh_programs_resyncs_existing_program_state():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context._programs_lock = threading.RLock()

    domain_file = Mock()
    domain_file.getPathname.return_value = "/folder/sample"

    program = Mock()
    program.getDomainFile.return_value = domain_file

    program_info = ProgramInfo(
        name="sample",
        program=program,
        flat_api=None,
        decompiler=Mock(),
        metadata={},
        ghidra_analysis_complete=False,
    )
    context.programs = {"/folder/sample": program_info}
    context._dispose_decompiler = Mock()
    context._init_program_info = Mock()
    context._get_program_managers = Mock(
        return_value=[Mock(getAllOpenPrograms=Mock(return_value=[program]))]
    )

    def sync(info, current_program):
        assert info is program_info
        assert current_program is program
        info.ghidra_analysis_complete = True

    context._sync_program_info = Mock(side_effect=sync)

    context.refresh_programs()

    assert context._sync_program_info.call_count == 1
    assert context.programs["/folder/sample"].analysis_complete is True


def test_gui_get_program_info_schedules_indexing_for_ready_binary():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    program_info = Mock()
    program_info.analysis_complete = True
    context._resolve_program_info = Mock(return_value=program_info)
    context.schedule_indexing = Mock()

    result = context.get_program_info("/folder/sample")

    assert result is program_info
    context.schedule_indexing.assert_called_once_with("/folder/sample")


def test_gui_schedule_startup_indexing_uses_open_programs():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context._programs_lock = threading.RLock()
    context.refresh_programs = Mock()
    context.programs = {
        "/folder/a": Mock(),
        "/folder/b": Mock(),
    }
    context.schedule_indexing = Mock()

    context.schedule_startup_indexing()

    context.schedule_indexing.assert_has_calls([call("/folder/a"), call("/folder/b")])


def test_gui_is_binary_file_uses_ghidra_importability(monkeypatch, tmp_path):
    candidate = tmp_path / "sample.bin"
    candidate.write_bytes(b"data")
    checked: list = []

    def fake_is_ghidra_importable(path):
        checked.append(path)
        return False

    monkeypatch.setattr(gui_context_module, "is_ghidra_importable", fake_is_ghidra_importable)

    assert GuiPyGhidraContext._is_binary_file(candidate) is False
    assert checked == [candidate]


def test_wait_for_gui_ready_opens_project_when_frontend_is_idle(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_gpr = project_dir / "proj.gpr"
    project_gpr.write_text("", encoding="utf-8")

    project_spec = Mock(
        project_directory=project_dir,
        gpr_path=project_gpr,
        project_name="proj",
    )

    opened_project = Mock()
    project_manager = Mock(getLastOpenedProject=Mock(return_value="locator"))
    front_end_tool = Mock(getProjectManager=Mock(return_value=project_manager))
    app_info = Mock(
        getActiveProject=Mock(side_effect=[None, opened_project]),
        getFrontEndTool=Mock(return_value=front_end_tool),
    )

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.framework.model",
        Mock(ProjectLocator=Mock(return_value="locator")),
    )
    monkeypatch.setattr(gui_context_module, "_run_on_swing", Mock(return_value=opened_project))
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is opened_project
    gui_context_module._run_on_swing.assert_called_once()
    project_manager.getLastOpenedProject.assert_not_called()


def test_wait_for_gui_ready_tolerates_frontend_not_running_yet(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_gpr = project_dir / "proj.gpr"
    project_gpr.write_text("", encoding="utf-8")

    project_spec = Mock(
        project_directory=project_dir,
        gpr_path=project_gpr,
        project_name="proj",
    )

    opened_project = Mock()
    project_manager = Mock(getLastOpenedProject=Mock(return_value="locator"))
    front_end_tool = Mock(getProjectManager=Mock(return_value=project_manager))
    app_info = Mock(
        getActiveProject=Mock(side_effect=[None, None, opened_project]),
        getFrontEndTool=Mock(side_effect=[RuntimeError("frontend not ready"), front_end_tool]),
    )

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.framework.model",
        Mock(ProjectLocator=Mock(return_value="locator")),
    )
    monkeypatch.setattr(gui_context_module, "_run_on_swing", Mock(return_value=opened_project))
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is opened_project
    gui_context_module._run_on_swing.assert_called_once()
