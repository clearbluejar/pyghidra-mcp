import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

from pyghidra_mcp.header_import.apply import HeaderImportApplyResult, apply_header_import_plan
from pyghidra_mcp.header_import.ir import BuiltinType, Diagnostic, HeaderImportPlan, TypedefDef
from pyghidra_mcp.tools import GhidraTools


def test_header_import_apply_result_preserves_name_fields_and_defaults_paths():
    result = HeaderImportApplyResult(
        category_root="/pyghidra_mcp/imported_headers",
        created_types=("Node",),
        updated_types=(),
    )

    assert result.created_types == ("Node",)
    assert result.created_type_paths == ()
    assert result.updated_type_paths == ()


def test_ghidra_tools_import_header_types_validate_only(monkeypatch, tmp_path):
    header_path = tmp_path / "sample.h"
    header_path.write_text("typedef int Value;\n", encoding="utf-8")

    plan = HeaderImportPlan(
        header_path=header_path,
        resolved_local_includes=(header_path,),
        resolved_system_includes=("stdint.h",),
        diagnostics=(Diagnostic(severity="warning", message="test warning"),),
    )

    monkeypatch.setattr(
        "pyghidra_mcp.header_import.planning.build_header_import_plan",
        lambda _header_path: plan,
    )

    program_info = Mock()
    program_info.program = Mock()
    program_info.decompiler_pool = Mock()
    tools = GhidraTools(program_info)

    response = tools.import_header_types(str(header_path), validate_only=True)

    assert response["header_path"] == str(header_path)
    assert response["validate_only"] is True
    assert response["created_types"] == []
    assert response["created_type_refs"] == []
    assert response["updated_type_refs"] == []
    assert "reused_types" not in response
    assert "reused_type_refs" not in response
    assert response["diagnostics"][0]["message"] == "test warning"


def test_ghidra_tools_import_header_types_dispatches_content_mode(monkeypatch):
    plan = HeaderImportPlan(
        header_path=Path("api_types.h"),
        resolved_local_includes=(),
        resolved_system_includes=(),
        diagnostics=(),
    )
    captured = {}

    def fake_build_from_source(header_content, *, header_name, include_files):
        captured["header_content"] = header_content
        captured["header_name"] = header_name
        captured["include_files"] = include_files
        return plan

    monkeypatch.setattr(
        "pyghidra_mcp.header_import.planning.build_header_import_plan_from_source",
        fake_build_from_source,
    )

    program_info = Mock()
    program_info.program = Mock()
    program_info.decompiler_pool = Mock()
    tools = GhidraTools(program_info)

    response = tools.import_header_types(
        validate_only=True,
        header_content="typedef int Count;",
        header_name="api_types.h",
        include_files={"shared.h": "typedef int Shared;"},
    )

    assert captured == {
        "header_content": "typedef int Count;",
        "header_name": "api_types.h",
        "include_files": {"shared.h": "typedef int Shared;"},
    }
    assert response["header_path"] == "api_types.h"
    assert response["validate_only"] is True


def test_ghidra_tools_import_header_types_dispatches_file_list_mode(monkeypatch):
    plan = HeaderImportPlan(
        header_path=Path("api_types.h"),
        resolved_local_includes=(),
        resolved_system_includes=(),
        diagnostics=(),
    )
    captured = {}

    def fake_build_from_files(header_files):
        captured["header_files"] = header_files
        return plan

    monkeypatch.setattr(
        "pyghidra_mcp.header_import.planning.build_header_import_plan_from_files",
        fake_build_from_files,
    )

    program_info = Mock()
    program_info.program = Mock()
    program_info.decompiler_pool = Mock()
    tools = GhidraTools(program_info)

    response = tools.import_header_types(
        validate_only=True,
        header_files=[
            {"name": "api_types.h", "content": "typedef int Count;"},
            {"name": "shared.h", "content": "typedef int Shared;"},
        ],
    )

    assert captured == {
        "header_files": [
            {"name": "api_types.h", "content": "typedef int Count;"},
            {"name": "shared.h", "content": "typedef int Shared;"},
        ]
    }
    assert response["header_path"] == "api_types.h"
    assert response["validate_only"] is True


def test_ghidra_tools_import_header_types_applies_plan(monkeypatch, tmp_path):
    header_path = tmp_path / "sample.h"
    header_path.write_text("typedef int Value;\n", encoding="utf-8")

    plan = HeaderImportPlan(
        header_path=header_path,
        resolved_local_includes=(header_path,),
        resolved_system_includes=(),
        diagnostics=(),
    )

    monkeypatch.setattr(
        "pyghidra_mcp.header_import.planning.build_header_import_plan",
        lambda _header_path: plan,
    )
    monkeypatch.setattr(
        "pyghidra_mcp.header_import.apply_header_import_plan",
        lambda _program, _plan: HeaderImportApplyResult(
            category_root="/pyghidra_mcp/imported_headers",
            created_types=("Node",),
            updated_types=(),
            created_type_paths=("/pyghidra_mcp/imported_headers/Node",),
        ),
    )

    program_info = Mock()
    program_info.program = Mock()
    program_info.program.startTransaction.return_value = 42
    program_info.decompiler_pool = Mock()
    tools = GhidraTools(program_info)
    tools.invalidate_decompiler_cache = Mock()
    tools._resolve_data_type = Mock(side_effect=lambda path: path)
    tools._serialize_data_type_reference = Mock(
        side_effect=lambda path: {
            "name": "Node",
            "display_name": "Node",
            "path": path,
            "category_path": "/pyghidra_mcp/imported_headers",
            "kind": "structure",
            "size": 16,
        }
    )

    response = tools.import_header_types(str(header_path), validate_only=False)

    assert response["category_root"] == "/pyghidra_mcp/imported_headers"
    assert response["created_types"] == ["Node"]
    assert response["created_type_refs"][0]["path"] == "/pyghidra_mcp/imported_headers/Node"
    program_info.program.startTransaction.assert_called_once_with("Import header types")
    program_info.program.endTransaction.assert_called_once_with(42, True)
    tools.invalidate_decompiler_cache.assert_called_once_with()


class FakeCategoryPath:
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return self.path


class FakeDataTypeConflictHandler:
    REPLACE_HANDLER = object()


class FakeBuiltinDataType:
    def __init__(self):
        self.name = self.__class__.__name__
        self.category = "/builtin"

    def getLength(self):  # noqa: N802
        return 0

    def getPathName(self):  # noqa: N802
        return f"{self.category}/{self.name}"


class FakeIntegerDataType(FakeBuiltinDataType):
    pass


class FakeLongLongDataType(FakeBuiltinDataType):
    pass


class FakeUnsignedLongLongDataType(FakeBuiltinDataType):
    pass


class FakeTypedefDataType:
    def __init__(self, category, name, target):
        self.category = str(category)
        self.name = name
        self.target = target

    def getPathName(self):  # noqa: N802
        return f"{self.category}/{self.name}"


class FakeDataTypeManager:
    def __init__(self):
        self.added = []

    def getDataType(self, _path):  # noqa: N802
        return None

    def addDataType(self, data_type, _handler):  # noqa: N802
        self.added.append(data_type)
        return data_type


class FakeProgramForHeaderApply:
    def __init__(self, pointer_size):
        self.pointer_size = pointer_size
        self.dtm = FakeDataTypeManager()

    def getDataTypeManager(self):  # noqa: N802
        return self.dtm

    def getDefaultPointerSize(self):  # noqa: N802
        return self.pointer_size


def _install_fake_ghidra_data_module(monkeypatch):
    ghidra = ModuleType("ghidra")
    program = ModuleType("ghidra.program")
    model = ModuleType("ghidra.program.model")
    data = ModuleType("ghidra.program.model.data")
    for name in (
        "ArrayDataType",
        "ByteDataType",
        "CharDataType",
        "DoubleDataType",
        "EnumDataType",
        "FloatDataType",
        "FunctionDefinitionDataType",
        "ParameterDefinitionImpl",
        "PointerDataType",
        "ShortDataType",
        "StructureDataType",
        "UnionDataType",
        "UnsignedCharDataType",
        "UnsignedIntegerDataType",
        "UnsignedShortDataType",
        "VoidDataType",
    ):
        setattr(data, name, FakeBuiltinDataType)
    data.CategoryPath = FakeCategoryPath
    data.DataTypeConflictHandler = FakeDataTypeConflictHandler
    data.IntegerDataType = FakeIntegerDataType
    data.LongLongDataType = FakeLongLongDataType
    data.UnsignedLongLongDataType = FakeUnsignedLongLongDataType
    data.TypedefDataType = FakeTypedefDataType
    monkeypatch.setitem(sys.modules, "ghidra", ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.program", program)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", model)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.data", data)


def test_apply_header_import_plan_maps_intptr_t_to_pointer_sized_signed_type(monkeypatch):
    _install_fake_ghidra_data_module(monkeypatch)
    plan = HeaderImportPlan(
        header_path=Path("types.h"),
        typedefs=(TypedefDef(name="SignedPtr", target=BuiltinType("intptr_t")),),
    )

    program32 = FakeProgramForHeaderApply(pointer_size=4)
    apply_header_import_plan(program32, plan)
    assert isinstance(program32.dtm.added[0].target, FakeIntegerDataType)

    program64 = FakeProgramForHeaderApply(pointer_size=8)
    apply_header_import_plan(program64, plan)
    assert isinstance(program64.dtm.added[0].target, FakeLongLongDataType)


def test_apply_header_import_plan_keeps_uintptr_t_pointer_sized_unsigned(monkeypatch):
    _install_fake_ghidra_data_module(monkeypatch)
    plan = HeaderImportPlan(
        header_path=Path("types.h"),
        typedefs=(TypedefDef(name="UnsignedPtr", target=BuiltinType("uintptr_t")),),
    )

    program64 = FakeProgramForHeaderApply(pointer_size=8)
    apply_header_import_plan(program64, plan)

    assert isinstance(program64.dtm.added[0].target, FakeUnsignedLongLongDataType)
