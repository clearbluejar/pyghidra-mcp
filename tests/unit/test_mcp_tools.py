from unittest.mock import Mock

from pyghidra_mcp.gui_context import GuiPyGhidraContext
from pyghidra_mcp.mcp_tools import goto, list_project_binaries, set_comment
from pyghidra_mcp.models import ProgramInfo


def test_list_project_binaries_uses_project_wide_context_listing():
    program_info = ProgramInfo(
        name="/folder/sample",
        file_path=None,
        load_time=None,
        analysis_complete=False,
        metadata={},
        code_indexed=False,
        strings_indexed=False,
    )
    pyghidra_context = Mock()
    pyghidra_context.list_project_binary_infos.return_value = [program_info]
    pyghidra_context.list_program_infos.side_effect = AssertionError(
        "should not use open-program listing"
    )

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    response = list_project_binaries(ctx)

    assert response.programs == [program_info]


def test_set_comment_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_comment.return_value = {
        "address": "1000042e3",
        "comment": "function summary",
        "comment_type": "decompiler",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = set_comment(
        binary_name="sample",
        target="entry",
        comment="function summary",
        comment_type="decompiler",
        ctx=ctx,
    )

    fake_tools.set_comment.assert_called_once_with("entry", "function summary", "decompiler")
    assert response.binary_name == "sample"
    assert response.address == "1000042e3"
    assert response.comment_type == "decompiler"


def test_goto_uses_gui_context():
    gui_context = GuiPyGhidraContext.__new__(GuiPyGhidraContext)
    gui_context.goto = Mock()
    gui_context.goto.return_value = {
        "binary_name": "sample",
        "address": "1000042e3",
        "success": True,
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = gui_context

    response = goto(
        binary_name="sample",
        target="entry",
        target_type="function",
        ctx=ctx,
    )

    gui_context.goto.assert_called_once_with("sample", "entry", "function")
    assert response.binary_name == "sample"
    assert response.address == "1000042e3"
    assert response.success is True
