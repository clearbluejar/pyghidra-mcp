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
        decompiler_pool=Mock(),
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


def test_wait_for_gui_ready_returns_active_project_without_forcing_open(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_gpr = project_dir / "proj.gpr"
    project_gpr.write_text("", encoding="utf-8")

    project_spec = Mock(
        project_directory=project_dir,
        gpr_path=project_gpr,
        project_name="proj",
    )

    active_project = Mock()
    app_info = Mock(getActiveProject=Mock(side_effect=[None, active_project]))

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is active_project


def test_wait_for_gui_ready_opens_requested_project_when_frontend_is_idle(monkeypatch, tmp_path):
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
    project_manager = Mock(openProject=Mock(return_value=opened_project))
    front_end_tool = Mock(
        getProjectManager=Mock(return_value=project_manager),
        setActiveProject=Mock(),
    )
    app_info = Mock(
        getActiveProject=Mock(side_effect=[None, None, opened_project]),
        getFrontEndTool=Mock(return_value=front_end_tool),
    )

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.framework.model",
        Mock(ProjectLocator=Mock(return_value="locator")),
    )
    monkeypatch.setattr(
        gui_context_module,
        "_run_on_swing",
        Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs)),
    )
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is opened_project
    gui_context_module._run_on_swing.assert_called_once()
    project_manager.openProject.assert_called_once_with("locator", True, False)
    front_end_tool.setActiveProject.assert_called_once_with(opened_project)


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

    active_project = Mock()
    app_info = Mock(getActiveProject=Mock(side_effect=[None, None, active_project]))

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is active_project


def test_open_program_in_gui_default_launches_new_window():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["ghidra.framework.model"] = Mock(DomainFile=Mock(DEFAULT_VERSION=1))
    sys.modules["java.util"] = Mock(List=Mock(of=Mock(side_effect=lambda value: [value])))
    tool_services = Mock(launchDefaultTool=Mock(return_value=Mock()))
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    context._find_domain_file = Mock(
        return_value=Mock(
            getPathname=Mock(return_value="/prog"),
        )
    )
    hidden_tool = Mock(
        getService=Mock(
            return_value=Mock(
                openProgram=Mock(),
                getCurrentProgram=Mock(return_value=Mock()),
            )
        )
    )
    context._get_primary_program_manager_tool = Mock(
        side_effect=[
            hidden_tool,
        ]
    )
    context._tool_is_visible = Mock(return_value=False)
    context.refresh_programs = Mock()
    context.schedule_indexing = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    program_manager = Mock(getCurrentProgram=Mock(return_value=Mock()))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    context._programs_lock = threading.RLock()
    context.programs = {
        "/prog": ProgramInfo(
            name="prog",
            program=Mock(),
            flat_api=None,
            decompiler_pool=Mock(),
            metadata={},
            ghidra_analysis_complete=True,
        )
    }

    result = context.open_program_in_gui("/prog")

    tool_services.launchDefaultTool.assert_called_once()
    assert result["path"] == "/prog"


def test_open_program_in_gui_new_window_launches_default_tool():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["java.util"] = Mock(List=Mock(of=Mock(side_effect=lambda value: [value])))
    tool_services = Mock(launchDefaultTool=Mock(return_value=Mock()))
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    context._find_domain_file = Mock(
        return_value=Mock(
            getPathname=Mock(return_value="/prog"),
        )
    )
    program_manager = Mock(getCurrentProgram=Mock(return_value=Mock()), openProgram=Mock())
    primary_tool = Mock(getService=Mock(return_value=program_manager))
    context._get_primary_program_manager_tool = Mock(return_value=primary_tool)
    context._tool_is_visible = Mock(return_value=True)
    context.refresh_programs = Mock()
    context.schedule_indexing = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    context._programs_lock = threading.RLock()
    context.programs = {
        "/prog": ProgramInfo(
            name="prog",
            program=Mock(),
            flat_api=None,
            decompiler_pool=Mock(),
            metadata={},
            ghidra_analysis_complete=True,
        )
    }

    result = context.open_program_in_gui("/prog", new_window=True)

    tool_services.launchDefaultTool.assert_called_once()
    program_manager.openProgram.assert_not_called()
    assert result["path"] == "/prog"


def test_open_program_in_gui_reuses_visible_tool_when_requested():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["ghidra.framework.model"] = Mock(DomainFile=Mock(DEFAULT_VERSION=1))

    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    tool_services = Mock(launchDefaultTool=Mock(return_value=Mock()))
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    domain_file = Mock(
        getPathname=Mock(return_value="/prog"),
    )
    context._find_domain_file = Mock(return_value=domain_file)
    program_manager = Mock(getCurrentProgram=Mock(return_value="program"), openProgram=Mock())
    primary_tool = Mock(getService=Mock(return_value=program_manager))
    context._get_primary_program_manager_tool = Mock(return_value=primary_tool)
    context._tool_is_visible = Mock(return_value=True)
    context.refresh_programs = Mock()
    context._programs_lock = threading.RLock()
    context.schedule_indexing = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    context.programs = {
        "/prog": ProgramInfo(
            name="prog",
            program="program",
            flat_api=None,
            decompiler_pool=Mock(),
            metadata={},
            ghidra_analysis_complete=True,
        )
    }

    result = context.open_program_in_gui("/prog", new_window=False)

    tool_services.launchDefaultTool.assert_not_called()
    program_manager.openProgram.assert_called_once()
    assert result["path"] == "/prog"


def test_open_program_in_gui_raises_clear_error_when_no_program_manager_after_launch():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["ghidra.framework.model"] = Mock(DomainFile=Mock(DEFAULT_VERSION=1))
    sys.modules["java.util"] = Mock(List=Mock(of=Mock(side_effect=lambda value: [value])))
    tool_services = Mock(
        launchDefaultTool=Mock(return_value=None),
        getRunningTools=Mock(return_value=[]),
    )
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    context._find_domain_file = Mock(
        return_value=Mock(
            getPathname=Mock(return_value="/prog"),
        )
    )
    context.refresh_programs = Mock()
    context._programs_lock = threading.RLock()
    context.programs = {}
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))

    with pytest.raises(RuntimeError, match="Timed out waiting for GUI to open program"):
        context.open_program_in_gui("/prog")


def test_tool_is_visible_prefers_frame_visibility():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(
        getToolFrame=Mock(return_value=Mock(isVisible=Mock(return_value=True))),
        getWindowManager=Mock(return_value=Mock(isVisible=Mock(return_value=False))),
    )

    assert context._tool_is_visible(tool) is True
