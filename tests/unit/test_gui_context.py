import threading
from unittest.mock import Mock

import pytest

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
