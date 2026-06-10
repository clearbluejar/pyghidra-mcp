import asyncio
from unittest.mock import Mock

import pytest

from pyghidra_mcp.gui_context import GuiPyGhidraContext
from pyghidra_mcp.mcp_tools import (
    decompile_function,
    describe_data_type,
    goto,
    import_header_types,
    list_data_types,
    list_project_binaries,
    rename_variable,
    search_symbols_by_name,
    set_comment,
    set_data_type_at_address,
    set_function_prototype,
    set_function_return_type,
    set_variable_type,
)
from pyghidra_mcp.models import ProgramInfo, SymbolInfo
from pyghidra_mcp.tools import GhidraTools


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
        variable_kind="local",
        ctx=ctx,
    )

    fake_tools.set_variable_type.assert_called_once_with(
        "helper", "total", "long", variable_kind="local"
    )
    assert response.binary_name == "sample"
    assert response.function_name == "helper"
    assert response.function_address == "100001000"
    assert response.variable_kind == "local"
    assert response.variable_name == "total"
    assert response.old_type == "int"
    assert response.new_type == "long"


def test_set_function_prototype_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_function_prototype.return_value = {
        "function_name": "function_one",
        "function_address": "100001000",
        "old_prototype": "int function_one(int count)",
        "new_prototype": "long function_one(long count)",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = set_function_prototype(
        binary_name="sample",
        function_name_or_address="function_one",
        prototype="long function_one(long count)",
        ctx=ctx,
    )

    fake_tools.set_function_prototype.assert_called_once_with(
        "function_one", "long function_one(long count)"
    )
    assert response.binary_name == "sample"
    assert response.function_name == "function_one"
    assert response.function_address == "100001000"
    assert response.old_prototype == "int function_one(int count)"
    assert response.new_prototype == "long function_one(long count)"


def test_set_function_return_type_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_function_return_type.return_value = {
        "function_name": "function_one",
        "function_address": "100001000",
        "old_return_type": "int",
        "old_return_type_path": "/builtin/int",
        "new_return_type": "Node",
        "new_return_type_path": "/pyghidra_mcp/imported_headers/Node",
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = set_function_return_type(
        binary_name="sample",
        function_name_or_address="function_one",
        type_name_or_path="/pyghidra_mcp/imported_headers/Node",
        ctx=ctx,
    )

    fake_tools.set_function_return_type.assert_called_once_with(
        "function_one", "/pyghidra_mcp/imported_headers/Node"
    )
    assert response.binary_name == "sample"
    assert response.function_name == "function_one"
    assert response.new_return_type_path == "/pyghidra_mcp/imported_headers/Node"


def test_set_data_type_at_address_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.set_data_type_at_address.return_value = {
        "address": "100001000",
        "old_type": None,
        "old_type_path": None,
        "new_type": "Node",
        "new_type_path": "/pyghidra_mcp/imported_headers/Node",
        "length": 16,
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = set_data_type_at_address(
        binary_name="sample",
        address="100001000",
        type_name_or_path="/pyghidra_mcp/imported_headers/Node",
        clear_existing=False,
        ctx=ctx,
    )

    fake_tools.set_data_type_at_address.assert_called_once_with(
        "100001000", "/pyghidra_mcp/imported_headers/Node", clear_existing=False
    )
    assert response.binary_name == "sample"
    assert response.address == "100001000"
    assert response.length == 16


def test_import_header_types_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.import_header_types.return_value = {
        "header_path": "/tmp/sample.h",
        "category_root": "/pyghidra_mcp/imported_headers",
        "validate_only": False,
        "resolved_local_includes": ["/tmp/sample.h"],
        "resolved_system_includes": ["stdint.h"],
        "created_types": ["Node"],
        "updated_types": [],
        "diagnostics": [],
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = import_header_types(
        binary_name="sample",
        header_path="/tmp/sample.h",
        validate_only=False,
        ctx=ctx,
    )

    fake_tools.import_header_types.assert_called_once_with(
        header_path="/tmp/sample.h",
        validate_only=False,
        header_content=None,
        header_name=None,
        include_files=None,
        header_files=None,
    )
    assert response.binary_name == "sample"
    assert response.header_path == "/tmp/sample.h"
    assert response.created_types == ["Node"]


def test_import_header_types_forwards_content_mode(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.import_header_types.return_value = {
        "header_path": "api_types.h",
        "category_root": "/pyghidra_mcp/imported_headers",
        "validate_only": True,
        "resolved_local_includes": ["api_types.h"],
        "resolved_system_includes": ["stdint.h"],
        "created_types": [],
        "updated_types": [],
        "diagnostics": [],
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = import_header_types(
        binary_name="sample",
        validate_only=True,
        ctx=ctx,
        header_content="#include <stdint.h>\ntypedef uint32_t ApiWord;",
        header_name="api_types.h",
        include_files={"shared.h": "typedef int Count;"},
    )

    fake_tools.import_header_types.assert_called_once_with(
        header_path=None,
        validate_only=True,
        header_content="#include <stdint.h>\ntypedef uint32_t ApiWord;",
        header_name="api_types.h",
        include_files={"shared.h": "typedef int Count;"},
        header_files=None,
    )
    assert response.binary_name == "sample"
    assert response.header_path == "api_types.h"
    assert response.validate_only is True


def test_import_header_types_forwards_file_list_mode(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.import_header_types.return_value = {
        "header_path": "api_types.h",
        "category_root": "/pyghidra_mcp/imported_headers",
        "validate_only": True,
        "resolved_local_includes": ["api_types.h"],
        "resolved_system_includes": [],
        "created_types": [],
        "updated_types": [],
        "diagnostics": [],
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    header_files = [
        {"name": "api_types.h", "content": "typedef int Count;"},
        {"name": "shared.h", "content": "typedef int Shared;"},
    ]
    response = import_header_types(
        binary_name="sample",
        validate_only=True,
        ctx=ctx,
        header_files=header_files,
    )

    fake_tools.import_header_types.assert_called_once_with(
        header_path=None,
        validate_only=True,
        header_content=None,
        header_name=None,
        include_files=None,
        header_files=header_files,
    )
    assert response.binary_name == "sample"
    assert response.header_path == "api_types.h"
    assert response.validate_only is True


def test_list_data_types_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.list_data_types.return_value = {
        "data_types": [
            {
                "name": "Node",
                "display_name": "Node",
                "path": "/pyghidra_mcp/imported_headers/Node",
                "category_path": "/pyghidra_mcp/imported_headers",
                "kind": "structure",
                "size": 16,
            }
        ],
        "total_matches": 1,
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = list_data_types(
        binary_name="sample",
        query="Node",
        category_path="/pyghidra_mcp/imported_headers",
        include_builtins=True,
        offset=2,
        limit=3,
        ctx=ctx,
    )

    fake_tools.list_data_types.assert_called_once_with(
        query="Node",
        category_path="/pyghidra_mcp/imported_headers",
        include_builtins=True,
        offset=2,
        limit=3,
    )
    assert response.total_matches == 1
    assert response.data_types[0].path == "/pyghidra_mcp/imported_headers/Node"


def test_describe_data_type_uses_tool_path(monkeypatch):
    pyghidra_context = Mock()
    pyghidra_context.get_program_info.return_value = Mock()

    fake_tools = Mock()
    fake_tools.describe_data_type.return_value = {
        "requested_name_or_path": "Node",
        "name": "Node",
        "display_name": "Node",
        "path": "/pyghidra_mcp/imported_headers/Node",
        "category_path": "/pyghidra_mcp/imported_headers",
        "kind": "structure",
        "size": 16,
        "aligned_size": 16,
        "description": "structure Node",
        "base_type_name": None,
        "base_type_path": None,
        "base_type_kind": None,
        "fields": [
            {
                "ordinal": 0,
                "offset": 0,
                "length": 8,
                "field_name": "next",
                "type_name": "Node *",
                "type_path": "/builtin/NodePtr",
                "comment": None,
            }
        ],
    }

    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context

    monkeypatch.setattr("pyghidra_mcp.mcp_tools.GhidraTools", lambda _program_info: fake_tools)

    response = describe_data_type(
        binary_name="sample",
        data_type_name_or_path="Node",
        ctx=ctx,
    )

    fake_tools.describe_data_type.assert_called_once_with("Node")
    assert response.binary_name == "sample"
    assert response.name == "Node"
    assert response.fields[0].field_name == "next"


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
            is_thunk=False,
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


class FakeAddress:
    def __init__(self, offset, *, max_offset=0xFFFF):
        self.offset = offset
        self.max_offset = max_offset

    def addNoWrap(self, delta):  # noqa: N802
        new_offset = self.offset + delta
        if new_offset > self.max_offset:
            raise OverflowError("address overflow")
        return FakeAddress(new_offset, max_offset=self.max_offset)

    def __str__(self):
        return f"{self.offset:x}"

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and self.offset == other.offset


class FakeAddressFactory:
    def __init__(self, addresses):
        self.addresses = addresses

    def getAddress(self, address):  # noqa: N802
        return self.addresses[address]


class FakeDataTypeForAddress:
    def __init__(self, length):
        self.length = length

    def getLength(self):  # noqa: N802
        return self.length

    def getDisplayName(self):  # noqa: N802
        return "FakeType"

    def getPathName(self):  # noqa: N802
        return "/types/FakeType"


class FakeDataAtAddress:
    def __init__(self, data_type):
        self.data_type = data_type

    def getDataType(self):  # noqa: N802
        return self.data_type

    def getLength(self):  # noqa: N802
        return self.data_type.getLength()


class FakeListing:
    def __init__(self):
        self.cleared = []
        self.created = []

    def getDefinedDataAt(self, _addr):  # noqa: N802
        return None

    def clearCodeUnits(self, start, end, clear_context):  # noqa: N802
        self.cleared.append((start, end, clear_context))

    def createData(self, addr, data_type):  # noqa: N802
        self.created.append((addr, data_type))
        return FakeDataAtAddress(data_type)


class FakeMemory:
    def __init__(self, mapped_offsets, blocks):
        self.mapped_offsets = set(mapped_offsets)
        self.blocks = blocks

    def contains(self, addr):
        return addr.offset in self.mapped_offsets

    def getBlock(self, addr):  # noqa: N802
        return self.blocks.get(addr.offset)


class FakeProgramForDataAtAddress:
    def __init__(self, memory, listing, addresses, pointer_size=8):
        self.memory = memory
        self.listing = listing
        self.address_factory = FakeAddressFactory(addresses)
        self.pointer_size = pointer_size
        self.transactions = []

    def getAddressFactory(self):  # noqa: N802
        return self.address_factory

    def getMemory(self):  # noqa: N802
        return self.memory

    def getListing(self):  # noqa: N802
        return self.listing

    def getDefaultPointerSize(self):  # noqa: N802
        return self.pointer_size

    def startTransaction(self, description):  # noqa: N802
        self.transactions.append(("start", description))
        return 1

    def endTransaction(self, tx_id, committed):  # noqa: N802
        self.transactions.append(("end", tx_id, committed))


def _tools_for_data_range(memory, listing, addresses, data_type):
    program_info = Mock()
    program_info.program = FakeProgramForDataAtAddress(memory, listing, addresses)
    program_info.decompiler_pool = Mock()
    tools = GhidraTools(program_info)
    tools._resolve_or_parse_data_type = Mock(return_value=data_type)
    tools.invalidate_decompiler_cache = Mock()
    return tools, program_info.program


def test_set_data_type_at_address_rejects_unmapped_end_before_transaction():
    start = FakeAddress(0x1000)
    memory = FakeMemory({0x1000}, {0x1000: "block"})
    listing = FakeListing()
    tools, program = _tools_for_data_range(
        memory, listing, {"1000": start}, FakeDataTypeForAddress(2)
    )

    with pytest.raises(ValueError, match="not fully mapped"):
        tools.set_data_type_at_address("1000", "FakeType")

    assert program.transactions == []
    assert listing.cleared == []
    assert listing.created == []


def test_set_data_type_at_address_rejects_ranges_that_cross_blocks_before_transaction():
    start = FakeAddress(0x1000)
    memory = FakeMemory({0x1000, 0x1001}, {0x1000: "block-a", 0x1001: "block-b"})
    listing = FakeListing()
    tools, program = _tools_for_data_range(
        memory, listing, {"1000": start}, FakeDataTypeForAddress(2)
    )

    with pytest.raises(ValueError, match="crosses memory blocks"):
        tools.set_data_type_at_address("1000", "FakeType")

    assert program.transactions == []
    assert listing.cleared == []
    assert listing.created == []


def test_set_data_type_at_address_rejects_address_overflow_before_transaction():
    start = FakeAddress(0xFFFF, max_offset=0xFFFF)
    memory = FakeMemory({0xFFFF}, {0xFFFF: "block"})
    listing = FakeListing()
    tools, program = _tools_for_data_range(
        memory, listing, {"ffff": start}, FakeDataTypeForAddress(2)
    )

    with pytest.raises(ValueError, match="does not fit"):
        tools.set_data_type_at_address("ffff", "FakeType")

    assert program.transactions == []
    assert listing.cleared == []
    assert listing.created == []


def test_set_data_type_at_address_validates_range_and_creates_data():
    start = FakeAddress(0x1000)
    data_type = FakeDataTypeForAddress(2)
    memory = FakeMemory({0x1000, 0x1001}, {0x1000: "block", 0x1001: "block"})
    listing = FakeListing()
    tools, program = _tools_for_data_range(memory, listing, {"1000": start}, data_type)

    result = tools.set_data_type_at_address("1000", "FakeType")

    assert result["address"] == "1000"
    assert result["length"] == 2
    assert listing.cleared == [(start, FakeAddress(0x1001), False)]
    assert listing.created == [(start, data_type)]
    assert program.transactions[0][0] == "start"
    assert program.transactions[-1] == ("end", 1, True)
