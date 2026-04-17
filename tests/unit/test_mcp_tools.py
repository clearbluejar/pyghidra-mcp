import asyncio
from unittest.mock import Mock

import pytest

from pyghidra_mcp.gui_context import GuiPyGhidraContext
from pyghidra_mcp.mcp_tools import (
    decompile_function,
    goto,
    list_project_binaries,
    rename_variable,
    search_symbols_by_name,
    set_comment,
    set_variable_type,
)
from pyghidra_mcp.models import ProgramInfo, SymbolInfo


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


def test_rename_variable_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.rename_variable.return_value = {
        "function_name": "helper",
        "function_address": "100001000",
        "variable_kind": "parameter",
        "old_name": "count",
        "new_name": "item_count",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = rename_variable(
        binary_name="sample",
        function_name_or_address="helper",
        variable_name="count",
        new_name="item_count",
        ctx=ctx,
    )

    fake_tools.rename_variable.assert_called_once_with("helper", "count", "item_count")
    assert response.binary_name == "sample"
    assert response.function_name == "helper"
    assert response.function_address == "100001000"
    assert response.variable_kind == "parameter"
    assert response.old_name == "count"
    assert response.new_name == "item_count"


def test_set_variable_type_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_variable_type.return_value = {
        "function_name": "helper",
        "function_address": "100001000",
        "variable_kind": "local",
        "variable_name": "total",
        "old_type": "int",
        "new_type": "long",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = set_variable_type(
        binary_name="sample",
        function_name_or_address="helper",
        variable_name="total",
        type_name="long",
        ctx=ctx,
    )

    fake_tools.set_variable_type.assert_called_once_with("helper", "total", "long")
    assert response.binary_name == "sample"
    assert response.function_name == "helper"
    assert response.function_address == "100001000"
    assert response.variable_kind == "local"
    assert response.variable_name == "total"
    assert response.old_type == "int"
    assert response.new_type == "long"


@pytest.mark.asyncio
async def test_decompile_function_offloads_with_timeout(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    decompiled = Mock()
    decompiled.callees = None
    decompiled.referenced_strings = None
    decompiled.xrefs = None
    fake_tools.decompile_function_by_name_or_addr.return_value = decompiled

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    response = await decompile_function(
        binary_name="sample",
        name_or_address="entry",
        timeout_sec=17,
        ctx=ctx,
    )

    fake_tools.decompile_function_by_name_or_addr.assert_called_once_with("entry", timeout=17)
    assert response == [decompiled]


@pytest.mark.asyncio
async def test_decompile_does_not_block_other_tool_calls(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    decompiled = Mock()
    fake_tools.search_symbols_by_name.return_value = [
        SymbolInfo(
            name="entry",
            address="1000",
            type="Function",
            namespace="Global",
            source="USER_DEFINED",
            refcount=1,
            external=False,
        )
    ]

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    decompile_started = asyncio.Event()
    release_decompile = asyncio.Event()

    async def fake_to_thread(fn, *args, **kwargs):
        decompile_started.set()
        await release_decompile.wait()
        return fn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    fake_tools.decompile_function_by_name_or_addr.return_value = decompiled

    decompile_task = asyncio.create_task(
        decompile_function(
            binary_name="sample",
            name_or_address="entry",
            timeout_sec=30,
            ctx=ctx,
        )
    )

    await decompile_started.wait()

    symbols = search_symbols_by_name(
        binary_name="sample",
        query="entry",
        ctx=ctx,
    )

    fake_tools.search_symbols_by_name.assert_called_once_with(
        "entry", functions_only=False, offset=0, limit=25
    )
    assert symbols.symbols[0].name == "entry"
    assert not decompile_task.done()

    release_decompile.set()
    response = await decompile_task
    assert response == [decompiled]


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
