import sys
import types
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import GhidraTools


class FakeCategoryPath:
    def __init__(self, path: str):
        self._path = path

    def getPath(self) -> str:
        return self._path


class BuiltinDataType:
    def __init__(self, name: str, path: str, length: int):
        self._name = name
        self._path = path
        self._length = length

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._name

    def getPathName(self) -> str:
        return self._path

    def getCategoryPath(self):
        category = self._path.rsplit("/", 1)[0] or "/"
        return FakeCategoryPath(category)

    def getLength(self) -> int:
        return self._length

    def getAlignedLength(self) -> int:
        return self._length

    def getDescription(self) -> str:
        return ""


class PointerDataType(BuiltinDataType):
    pass


class FakeDataTypeComponent:
    def __init__(
        self,
        ordinal: int,
        offset: int,
        length: int,
        field_name: str,
        data_type,
        comment: str | None = None,
    ):
        self._ordinal = ordinal
        self._offset = offset
        self._length = length
        self._field_name = field_name
        self._data_type = data_type
        self._comment = comment

    def getOrdinal(self) -> int:
        return self._ordinal

    def getOffset(self) -> int:
        return self._offset

    def getLength(self) -> int:
        return self._length

    def getFieldName(self) -> str:
        return self._field_name

    def getDefaultFieldName(self) -> str:
        return self._field_name

    def getDataType(self):
        return self._data_type

    def getComment(self) -> str | None:
        return self._comment


class StructureDataType(BuiltinDataType):
    def __init__(self, name: str, path: str, length: int, components):
        super().__init__(name, path, length)
        self._components = components

    def getDefinedComponents(self):
        return list(self._components)

    def getDescription(self) -> str:
        return f"structure {self._name}"


class TypedefDataType(BuiltinDataType):
    def __init__(self, name: str, path: str, length: int, base_type):
        super().__init__(name, path, length)
        self._base_type = base_type

    def getBaseDataType(self):
        return self._base_type


class FakeIterator:
    def __init__(self, values):
        self._values = list(values)
        self._index = 0

    def hasNext(self) -> bool:
        return self._index < len(self._values)

    def next(self):
        value = self._values[self._index]
        self._index += 1
        return value


class FakeDataTypeManager:
    def __init__(self, data_types):
        self._data_types = list(data_types)

    def getAllDataTypes(self):
        return FakeIterator(self._data_types)


def _make_tools(*data_types: object) -> GhidraTools:
    program = Mock()
    program.getDataTypeManager.return_value = FakeDataTypeManager(data_types)
    program_info = Mock()
    program_info.program = program
    program_info.decompiler_pool = Mock()
    return GhidraTools(program_info)


def test_describe_data_type_by_exact_name_returns_field_layout():
    int_type = BuiltinDataType("int", "/builtin/int", 4)
    node_type = StructureDataType(
        "Node",
        "/pyghidra_mcp/imported_headers/Node",
        16,
        [
            FakeDataTypeComponent(0, 0, 8, "next", PointerDataType("Node *", "/builtin/NodePtr", 8)),
            FakeDataTypeComponent(1, 8, 4, "value", int_type, "payload"),
        ],
    )
    tools = _make_tools(node_type)

    response = tools.describe_data_type("Node")

    assert response["name"] == "Node"
    assert response["kind"] == "structure"
    assert response["path"] == "/pyghidra_mcp/imported_headers/Node"
    assert response["fields"][0]["field_name"] == "next"
    assert response["fields"][0]["offset"] == 0
    assert response["fields"][1]["field_name"] == "value"
    assert response["fields"][1]["type_name"] == "int"
    assert response["fields"][1]["comment"] == "payload"


def test_describe_data_type_rejects_ambiguous_exact_name():
    first = BuiltinDataType("Node", "/types/Node", 4)
    second = BuiltinDataType("Node", "/other/Node", 8)
    tools = _make_tools(first, second)

    with pytest.raises(ValueError, match="Ambiguous data type 'Node'"):
        tools.describe_data_type("Node")


def test_describe_data_type_typedef_reports_base_type_and_fields():
    word_type = BuiltinDataType("Word", "/pyghidra_mcp/imported_headers/Word", 4)
    runtime_struct = StructureDataType(
        "Runtime",
        "/pyghidra_mcp/imported_headers/Runtime",
        8,
        [FakeDataTypeComponent(0, 0, 4, "value", word_type)],
    )
    runtime_alias = TypedefDataType(
        "RuntimeAlias",
        "/pyghidra_mcp/imported_headers/RuntimeAlias",
        8,
        runtime_struct,
    )
    tools = _make_tools(runtime_alias)

    response = tools.describe_data_type("/pyghidra_mcp/imported_headers/RuntimeAlias")

    assert response["name"] == "RuntimeAlias"
    assert response["kind"] == "typedef"
    assert response["base_type_name"] == "Runtime"
    assert response["base_type_path"] == "/pyghidra_mcp/imported_headers/Runtime"
    assert response["base_type_kind"] == "structure"
    assert response["fields"][0]["field_name"] == "value"


def test_resolve_or_parse_data_type_resolves_full_path_first():
    node_type = StructureDataType("Node", "/pyghidra_mcp/imported_headers/Node", 16, [])
    tools = _make_tools(node_type)
    tools._parse_data_type = Mock(side_effect=AssertionError("parser should not be used"))

    result = tools._resolve_or_parse_data_type("/pyghidra_mcp/imported_headers/Node")

    assert result is node_type


def test_resolve_or_parse_data_type_preserves_ambiguous_name_error():
    first = BuiltinDataType("Node", "/types/Node", 4)
    second = BuiltinDataType("Node", "/other/Node", 8)
    tools = _make_tools(first, second)
    tools._parse_data_type = Mock(side_effect=AssertionError("parser should not be used"))

    with pytest.raises(ValueError, match="Matching paths: /other/Node, /types/Node"):
        tools._resolve_or_parse_data_type("Node")


def test_resolve_or_parse_data_type_falls_back_to_parser_for_declarators():
    parsed_type = PointerDataType("Node *", "/builtin/NodePtr", 8)
    tools = _make_tools()
    tools._parse_data_type = Mock(return_value=parsed_type)

    result = tools._resolve_or_parse_data_type("Node *")

    assert result is parsed_type
    tools._parse_data_type.assert_called_once_with("Node *")


def test_list_data_types_filters_by_category_query_and_paginates():
    node_type = StructureDataType("Node", "/pyghidra_mcp/imported_headers/Node", 16, [])
    word_type = TypedefDataType("Word", "/pyghidra_mcp/imported_headers/Word", 4, node_type)
    builtin_type = BuiltinDataType("int", "/builtin/int", 4)
    tools = _make_tools(word_type, builtin_type, node_type)

    response = tools.list_data_types(
        query="node|word",
        category_path="/pyghidra_mcp/imported_headers",
        offset=1,
        limit=1,
    )

    assert response["total_matches"] == 2
    assert [data_type["path"] for data_type in response["data_types"]] == [
        "/pyghidra_mcp/imported_headers/Word"
    ]


def test_list_data_types_default_excludes_builtins_and_includes_project_types():
    node_type = StructureDataType("Node", "/pyghidra_mcp/imported_headers/Node", 16, [])
    runtime_type = StructureDataType("Runtime", "/project/Runtime", 8, [])
    builtin_type = BuiltinDataType("int", "/builtin/int", 4)
    tools = _make_tools(builtin_type, runtime_type, node_type)

    response = tools.list_data_types(query=".*")

    assert [data_type["path"] for data_type in response["data_types"]] == [
        "/project/Runtime",
        "/pyghidra_mcp/imported_headers/Node",
    ]


def _install_fake_source_type(monkeypatch):
    ghidra = types.ModuleType("ghidra")
    program = types.ModuleType("ghidra.program")
    model = types.ModuleType("ghidra.program.model")
    symbol = types.ModuleType("ghidra.program.model.symbol")
    symbol.SourceType = types.SimpleNamespace(USER_DEFINED=object())
    monkeypatch.setitem(sys.modules, "ghidra", ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.program", program)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", model)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", symbol)


class FakeVariable:
    def __init__(self, name: str, data_type):
        self._name = name
        self._data_type = data_type

    def getName(self) -> str:
        return self._name

    def getDataType(self):
        return self._data_type

    def setDataType(self, data_type, _source_type):
        self._data_type = data_type


class FakeFunction:
    def __init__(self, variable):
        self._variable = variable

    def getName(self) -> str:
        return "helper"

    def getEntryPoint(self) -> str:
        return "1000"

    def getParameters(self):
        return []

    def getLocalVariables(self):
        return [self._variable]


def test_set_variable_type_uses_exact_imported_datatype_path(monkeypatch):
    _install_fake_source_type(monkeypatch)
    int_type = BuiltinDataType("int", "/builtin/int", 4)
    node_type = StructureDataType("Node", "/pyghidra_mcp/imported_headers/Node", 16, [])
    variable = FakeVariable("node", int_type)
    tools = _make_tools(node_type, int_type)
    tools.find_function = Mock(return_value=FakeFunction(variable))

    response = tools.set_variable_type(
        "helper",
        "node",
        "/pyghidra_mcp/imported_headers/Node",
        variable_kind="local",
    )

    assert variable.getDataType() is node_type
    assert response["old_type_path"] == "/builtin/int"
    assert response["new_type_path"] == "/pyghidra_mcp/imported_headers/Node"
    assert response["variable_kind"] == "local"
