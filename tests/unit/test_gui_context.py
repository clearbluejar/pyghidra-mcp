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
    project_manager = Mock(
        createProject=Mock(),
        openProject=Mock(return_value=opened_project),
    )
    front_end_tool = Mock(
        getProjectManager=Mock(return_value=project_manager),
        setActiveProject=Mock(),
    )
    locator = Mock(exists=Mock(return_value=True))
    app_info = Mock(
        getActiveProject=Mock(side_effect=[None, None, opened_project]),
        getFrontEndTool=Mock(return_value=front_end_tool),
    )

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.framework.model",
        Mock(ProjectLocator=Mock(return_value=locator)),
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
    project_manager.openProject.assert_called_once_with(locator, True, False)
    project_manager.createProject.assert_not_called()
    front_end_tool.setActiveProject.assert_not_called()


def test_wait_for_gui_ready_creates_requested_project_when_missing(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    project_gpr = project_dir / "proj.gpr"

    project_spec = Mock(
        project_directory=project_dir,
        gpr_path=project_gpr,
        project_name="proj",
    )

    created_project = Mock()
    project_manager = Mock(
        createProject=Mock(return_value=created_project),
        openProject=Mock(),
    )
    front_end_tool = Mock(
        getProjectManager=Mock(return_value=project_manager),
        setActiveProject=Mock(),
    )
    locator = Mock(exists=Mock(return_value=False))
    app_info = Mock(
        getActiveProject=Mock(side_effect=[None, None, created_project]),
        getFrontEndTool=Mock(return_value=front_end_tool),
    )

    monkeypatch.setitem(sys.modules, "ghidra.framework.main", Mock(AppInfo=app_info))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.framework.model",
        Mock(ProjectLocator=Mock(return_value=locator)),
    )
    monkeypatch.setattr(
        gui_context_module,
        "_run_on_swing",
        Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs)),
    )
    monkeypatch.setattr(gui_context_module.time, "sleep", Mock())

    project = GuiPyGhidraContext.wait_for_gui_ready(project_spec, timeout=1, interval=0)

    assert project is created_project
    assert project_dir.exists()
    gui_context_module._run_on_swing.assert_called_once()
    project_manager.createProject.assert_called_once_with(locator, None, True)
    project_manager.openProject.assert_not_called()
    front_end_tool.setActiveProject.assert_not_called()


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
    prepared_program = Mock()
    context._prepare_domain_file_for_gui_open = Mock(return_value=prepared_program)
    context._release_prepared_program = Mock()
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
    context.schedule_indexing = Mock()
    context._start_gui_analysis_if_needed = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    program_manager = Mock(getCurrentProgram=Mock(return_value=Mock()))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    context._programs_lock = threading.RLock()
    program_info = ProgramInfo(
        name="prog",
        program=Mock(),
        flat_api=None,
        decompiler_pool=Mock(),
        metadata={},
        ghidra_analysis_complete=True,
    )
    context.programs = {}

    def refresh_programs():
        if tool_services.launchDefaultTool.called:
            context.programs["/prog"] = program_info

    context.refresh_programs = Mock(side_effect=refresh_programs)

    result = context.open_program_in_gui("/prog")

    tool_services.launchDefaultTool.assert_called_once()
    context._prepare_domain_file_for_gui_open.assert_called_once()
    context._release_prepared_program.assert_called_once_with(prepared_program)
    context._start_gui_analysis_if_needed.assert_called_once()
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
    prepared_program = Mock()
    context._prepare_domain_file_for_gui_open = Mock(return_value=prepared_program)
    context._release_prepared_program = Mock()
    program_manager = Mock(getCurrentProgram=Mock(return_value=Mock()), openProgram=Mock())
    primary_tool = Mock(getService=Mock(return_value=program_manager))
    context._get_primary_program_manager_tool = Mock(return_value=primary_tool)
    context._tool_is_visible = Mock(return_value=True)
    context.schedule_indexing = Mock()
    context._start_gui_analysis_if_needed = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    context._programs_lock = threading.RLock()
    program_info = ProgramInfo(
        name="prog",
        program=Mock(),
        flat_api=None,
        decompiler_pool=Mock(),
        metadata={},
        ghidra_analysis_complete=True,
    )
    context.programs = {}

    def refresh_programs():
        if tool_services.launchDefaultTool.called:
            context.programs["/prog"] = program_info

    context.refresh_programs = Mock(side_effect=refresh_programs)

    result = context.open_program_in_gui("/prog", new_window=True)

    tool_services.launchDefaultTool.assert_called_once()
    program_manager.openProgram.assert_not_called()
    context._prepare_domain_file_for_gui_open.assert_called_once()
    context._release_prepared_program.assert_called_once_with(prepared_program)
    context._start_gui_analysis_if_needed.assert_called_once()
    assert result["path"] == "/prog"


def test_open_program_in_gui_reuses_already_open_program():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["ghidra.framework.model"] = Mock(DomainFile=Mock(DEFAULT_VERSION=1))
    sys.modules["java.util"] = Mock(List=Mock(of=Mock(side_effect=lambda value: [value])))

    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    tool_services = Mock(launchDefaultTool=Mock(return_value=Mock()))
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    domain_file = Mock(
        getPathname=Mock(return_value="/prog"),
    )
    context._find_domain_file = Mock(return_value=domain_file)
    prepared_program = Mock()
    context._prepare_domain_file_for_gui_open = Mock(return_value=prepared_program)
    context._release_prepared_program = Mock()
    program_manager = Mock(getCurrentProgram=Mock(return_value="program"), openProgram=Mock())
    primary_tool = Mock(getService=Mock(return_value=program_manager))
    context._get_primary_program_manager_tool = Mock(return_value=primary_tool)
    context._tool_is_visible = Mock(return_value=True)
    context.refresh_programs = Mock()
    context._programs_lock = threading.RLock()
    context.schedule_indexing = Mock()
    context._start_gui_analysis_if_needed = Mock()
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

    result = context.open_program_in_gui("/prog", new_window=True)

    tool_services.launchDefaultTool.assert_not_called()
    program_manager.openProgram.assert_called_once_with("program", 2)
    tool.setVisible.assert_called_once_with(True)
    context._prepare_domain_file_for_gui_open.assert_not_called()
    context._release_prepared_program.assert_not_called()
    context._start_gui_analysis_if_needed.assert_called_once_with("program")
    assert result["path"] == "/prog"


def test_open_program_in_gui_reuses_visible_tool_when_requested():
    sys.modules["ghidra.app.services"] = Mock(ProgramManager=Mock(OPEN_CURRENT=1, OPEN_VISIBLE=2))
    sys.modules["ghidra.framework.model"] = Mock(DomainFile=Mock(DEFAULT_VERSION=1))
    sys.modules["java.util"] = Mock(List=Mock(of=Mock(side_effect=lambda value: [value])))

    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    tool_services = Mock(launchDefaultTool=Mock(return_value=Mock()))
    context.project = Mock(getToolServices=Mock(return_value=tool_services))
    domain_file = Mock(getPathname=Mock(return_value="/prog"))
    domain_file.DEFAULT_VERSION = 1
    context._find_domain_file = Mock(return_value=domain_file)
    prepared_program = Mock()
    context._prepare_domain_file_for_gui_open = Mock(return_value=prepared_program)
    context._release_prepared_program = Mock()
    program_manager = Mock(getCurrentProgram=Mock(return_value="program"), openProgram=Mock())
    primary_tool = Mock(getService=Mock(return_value=program_manager))
    context._get_primary_program_manager_tool = Mock(return_value=primary_tool)
    context._tool_is_visible = Mock(return_value=True)
    context._programs_lock = threading.RLock()
    context.schedule_indexing = Mock()
    context._start_gui_analysis_if_needed = Mock()
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(getService=Mock(return_value=program_manager))
    context._find_tool_for_program = Mock(return_value=tool)
    program_info = ProgramInfo(
        name="prog",
        program="program",
        flat_api=None,
        decompiler_pool=Mock(),
        metadata={},
        ghidra_analysis_complete=True,
    )
    context.programs = {}

    def refresh_programs():
        if program_manager.openProgram.called:
            context.programs["/prog"] = program_info

    context.refresh_programs = Mock(side_effect=refresh_programs)

    result = context.open_program_in_gui("/prog", new_window=False)

    tool_services.launchDefaultTool.assert_not_called()
    program_manager.openProgram.assert_called_once_with(domain_file, 1, 2)
    context._prepare_domain_file_for_gui_open.assert_called_once_with(domain_file)
    context._release_prepared_program.assert_called_once_with(prepared_program)
    context._start_gui_analysis_if_needed.assert_called_once_with("program")
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
    prepared_program = Mock()
    context._prepare_domain_file_for_gui_open = Mock(return_value=prepared_program)
    context._release_prepared_program = Mock()
    context.refresh_programs = Mock()
    context._programs_lock = threading.RLock()
    context.programs = {}
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))

    with pytest.raises(RuntimeError, match="Timed out waiting for GUI to open program"):
        context.open_program_in_gui("/prog")

    context._release_prepared_program.assert_called_once_with(prepared_program)


def test_set_current_program_reuses_existing_window():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.open_program_in_gui = Mock(return_value={"path": "/prog", "current": True})

    result = context.set_current_program("/prog")

    context.open_program_in_gui.assert_called_once_with(
        "/prog",
        current=True,
        new_window=False,
    )
    assert result["current"] is True


def test_tool_is_visible_prefers_frame_visibility():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    context.run_on_swing = Mock(side_effect=lambda fn, *args, **kwargs: fn(*args, **kwargs))
    tool = Mock(
        getToolFrame=Mock(return_value=Mock(isVisible=Mock(return_value=True))),
        getWindowManager=Mock(return_value=Mock(isVisible=Mock(return_value=False))),
    )

    assert context._tool_is_visible(tool) is True


def test_prepare_domain_file_for_gui_open_marks_and_saves_closed_program(monkeypatch):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    task_monitor = Mock(DUMMY="dummy-monitor")
    program = Mock()
    context._get_gui_program_consumer = Mock(return_value="consumer")
    domain_file = Mock(
        getOpenedDomainObject=Mock(return_value=None),
        getDomainObject=Mock(return_value=program),
    )
    context._mark_program_not_to_ask_to_analyze = Mock(return_value=True)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", Mock(TaskMonitor=task_monitor))

    prepared = context._prepare_domain_file_for_gui_open(domain_file)

    assert prepared is program
    domain_file.getOpenedDomainObject.assert_called_once_with("consumer")
    domain_file.getDomainObject.assert_called_once_with("consumer", True, False, "dummy-monitor")
    context._mark_program_not_to_ask_to_analyze.assert_called_once_with(program)
    program.save.assert_called_once_with(
        "pyghidra-mcp: suppress GUI analysis prompt",
        "dummy-monitor",
    )
    program.release.assert_not_called()


def test_prepare_domain_file_for_gui_open_does_not_save_when_prompt_flag_unchanged(
    monkeypatch,
):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    task_monitor = Mock(DUMMY="dummy-monitor")
    program = Mock()
    context._get_gui_program_consumer = Mock(return_value="consumer")
    domain_file = Mock(
        getOpenedDomainObject=Mock(return_value=None),
        getDomainObject=Mock(return_value=program),
    )
    context._mark_program_not_to_ask_to_analyze = Mock(return_value=False)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", Mock(TaskMonitor=task_monitor))

    prepared = context._prepare_domain_file_for_gui_open(domain_file)

    assert prepared is program
    program.save.assert_not_called()
    program.release.assert_not_called()


def test_prepare_domain_file_for_gui_open_releases_program_on_error(monkeypatch):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    task_monitor = Mock(DUMMY="dummy-monitor")
    program = Mock()
    context._get_gui_program_consumer = Mock(return_value="consumer")
    domain_file = Mock(
        getOpenedDomainObject=Mock(return_value=None),
        getDomainObject=Mock(return_value=program),
    )
    context._mark_program_not_to_ask_to_analyze = Mock(side_effect=RuntimeError("boom"))
    monkeypatch.setitem(sys.modules, "ghidra.util.task", Mock(TaskMonitor=task_monitor))

    with pytest.raises(RuntimeError, match="boom"):
        context._prepare_domain_file_for_gui_open(domain_file)

    program.release.assert_called_once_with("consumer")


def test_release_prepared_program_uses_gui_consumer():
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    program = Mock()
    context._get_gui_program_consumer = Mock(return_value="consumer")

    context._release_prepared_program(program)

    program.release.assert_called_once_with("consumer")


def test_mark_program_not_to_ask_to_analyze_only_when_needed(monkeypatch):
    program = Mock()
    utilities = Mock(
        shouldAskToAnalyze=Mock(return_value=True),
        markProgramNotToAskToAnalyze=Mock(),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )

    changed = GuiPyGhidraContext._mark_program_not_to_ask_to_analyze(program)

    utilities.shouldAskToAnalyze.assert_called_once_with(program)
    utilities.markProgramNotToAskToAnalyze.assert_called_once_with(program)
    assert changed is True


def test_mark_program_not_to_ask_to_analyze_returns_false_when_already_suppressed(
    monkeypatch,
):
    program = Mock()
    utilities = Mock(
        shouldAskToAnalyze=Mock(return_value=False),
        markProgramNotToAskToAnalyze=Mock(),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )

    changed = GuiPyGhidraContext._mark_program_not_to_ask_to_analyze(program)

    utilities.shouldAskToAnalyze.assert_called_once_with(program)
    utilities.markProgramNotToAskToAnalyze.assert_not_called()
    assert changed is False


def test_is_program_analysis_complete_requires_analyzed_flag(monkeypatch):
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=False))
    auto_analysis_manager = Mock()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(AutoAnalysisManager=auto_analysis_manager),
    )

    assert GuiPyGhidraContext._is_program_analysis_complete(program) is False
    auto_analysis_manager.getAnalysisManager.assert_not_called()


def test_is_program_analysis_complete_false_while_gui_analysis_runs(monkeypatch):
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=True))
    analysis_manager = Mock(isAnalyzing=Mock(return_value=True))
    auto_analysis_manager = Mock(getAnalysisManager=Mock(return_value=analysis_manager))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(AutoAnalysisManager=auto_analysis_manager),
    )

    assert GuiPyGhidraContext._is_program_analysis_complete(program) is False
    auto_analysis_manager.getAnalysisManager.assert_called_once_with(program)


def test_is_program_analysis_complete_true_after_gui_analysis_finishes(monkeypatch):
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=True))
    analysis_manager = Mock(isAnalyzing=Mock(return_value=False))
    auto_analysis_manager = Mock(getAnalysisManager=Mock(return_value=analysis_manager))
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(AutoAnalysisManager=auto_analysis_manager),
    )

    assert GuiPyGhidraContext._is_program_analysis_complete(program) is True
    auto_analysis_manager.getAnalysisManager.assert_called_once_with(program)


def test_start_gui_analysis_marks_no_prompt_and_starts_background_analysis(monkeypatch):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=False))
    analysis_manager = Mock(
        isAnalyzing=Mock(return_value=False),
        initializeOptions=Mock(),
        reAnalyzeAll=Mock(),
    )
    auto_analysis_manager = Mock(getAnalysisManager=Mock(return_value=analysis_manager))
    background_command = Mock()
    analysis_background_command = Mock(return_value=background_command)
    tool = Mock(executeBackgroundCommand=Mock())
    context._find_tool_for_program = Mock(return_value=tool)
    context._mark_program_not_to_ask_to_analyze = Mock()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(
            AnalysisBackgroundCommand=analysis_background_command,
            AutoAnalysisManager=auto_analysis_manager,
        ),
    )

    context._start_gui_analysis_if_needed(program)

    utilities.isAnalyzed.assert_called_once_with(program)
    context._mark_program_not_to_ask_to_analyze.assert_called_once_with(program)
    auto_analysis_manager.getAnalysisManager.assert_called_once_with(program)
    analysis_manager.initializeOptions.assert_called_once_with()
    analysis_manager.reAnalyzeAll.assert_called_once_with(None)
    context._find_tool_for_program.assert_called_once_with(program)
    analysis_background_command.assert_called_once_with(analysis_manager, True)
    tool.executeBackgroundCommand.assert_called_once_with(background_command, program)


def test_start_gui_analysis_skips_when_analysis_is_already_running(monkeypatch):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=False))
    analysis_manager = Mock(isAnalyzing=Mock(return_value=True))
    auto_analysis_manager = Mock(getAnalysisManager=Mock(return_value=analysis_manager))
    context._mark_program_not_to_ask_to_analyze = Mock()
    context._find_tool_for_program = Mock()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(AnalysisBackgroundCommand=Mock(), AutoAnalysisManager=auto_analysis_manager),
    )

    context._start_gui_analysis_if_needed(program)

    context._mark_program_not_to_ask_to_analyze.assert_called_once_with(program)
    auto_analysis_manager.getAnalysisManager.assert_called_once_with(program)
    analysis_manager.initializeOptions.assert_not_called()
    analysis_manager.reAnalyzeAll.assert_not_called()
    context._find_tool_for_program.assert_not_called()


def test_start_gui_analysis_skips_analyzed_program(monkeypatch):
    context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    program = Mock()
    utilities = Mock(isAnalyzed=Mock(return_value=True))
    auto_analysis_manager = Mock()
    context._mark_program_not_to_ask_to_analyze = Mock()
    monkeypatch.setitem(
        sys.modules,
        "ghidra.program.util",
        Mock(GhidraProgramUtilities=utilities),
    )
    monkeypatch.setitem(
        sys.modules,
        "ghidra.app.plugin.core.analysis",
        Mock(AnalysisBackgroundCommand=Mock(), AutoAnalysisManager=auto_analysis_manager),
    )

    context._start_gui_analysis_if_needed(program)

    context._mark_program_not_to_ask_to_analyze.assert_not_called()
    auto_analysis_manager.getAnalysisManager.assert_not_called()
