from unittest.mock import Mock

from pyghidra_mcp.tools import GhidraTools


class _FakeSymbol:
    def __init__(
        self,
        name: str,
        address: str,
        *,
        external_entry: bool = True,
        namespace: str = "libc.so",
    ):
        self._name = name
        self._address = address
        self._external_entry = external_entry
        self._namespace = namespace

    def getName(self):  # noqa: N802
        return self._name

    def getAddress(self):  # noqa: N802
        return self._address

    def getParentNamespace(self):  # noqa: N802
        return self._namespace

    def isExternalEntryPoint(self):  # noqa: N802
        return self._external_entry


def _make_tools(program):
    tools = GhidraTools.__new__(GhidraTools)
    tools.program = program
    return tools


def test_list_exports_stops_after_requested_page():
    yielded = []
    symbols = [
        _FakeSymbol("export_0", "0x1000"),
        _FakeSymbol("export_1", "0x1001"),
        _FakeSymbol("export_2", "0x1002"),
        _FakeSymbol("export_3", "0x1003"),
        _FakeSymbol("export_4", "0x1004"),
    ]

    def iter_symbols():
        for symbol in symbols:
            yielded.append(symbol.getName())
            yield symbol

    program = Mock()
    program.getSymbolTable.return_value.getAllSymbols.return_value = iter_symbols()

    results = _make_tools(program).list_exports(query="export", offset=1, limit=2)

    assert [result.name for result in results] == ["export_1", "export_2"]
    assert yielded == ["export_0", "export_1", "export_2"]
    program.getSymbolTable.return_value.getAllSymbols.assert_called_once_with(True)


def test_list_exports_skips_non_entry_points_without_counting_them():
    yielded = []
    symbols = [
        _FakeSymbol("label_0", "0x1000", external_entry=False),
        _FakeSymbol("export_0", "0x1001"),
        _FakeSymbol("export_1", "0x1002"),
        _FakeSymbol("export_2", "0x1003"),
        _FakeSymbol("export_3", "0x1004"),
    ]

    def iter_symbols():
        for symbol in symbols:
            yielded.append(symbol.getName())
            yield symbol

    program = Mock()
    program.getSymbolTable.return_value.getAllSymbols.return_value = iter_symbols()

    results = _make_tools(program).list_exports(query="export", offset=1, limit=2)

    assert [result.name for result in results] == ["export_1", "export_2"]
    assert yielded == ["label_0", "export_0", "export_1", "export_2"]


def test_list_imports_stops_after_requested_page():
    yielded = []
    symbols = [
        _FakeSymbol("import_0", "0x2000"),
        _FakeSymbol("import_1", "0x2001"),
        _FakeSymbol("import_2", "0x2002"),
        _FakeSymbol("import_3", "0x2003"),
        _FakeSymbol("import_4", "0x2004"),
    ]

    def iter_symbols():
        for symbol in symbols:
            yielded.append(symbol.getName())
            yield symbol

    program = Mock()
    program.getSymbolTable.return_value.getExternalSymbols.return_value = iter_symbols()

    results = _make_tools(program).list_imports(query="import", offset=1, limit=2)

    assert [result.name for result in results] == ["import_1", "import_2"]
    assert yielded == ["import_0", "import_1", "import_2"]
    program.getSymbolTable.return_value.getExternalSymbols.assert_called_once_with()


def test_list_imports_returns_empty_without_scanning_when_limit_is_zero():
    program = Mock()
    program.getSymbolTable.return_value.getExternalSymbols.side_effect = AssertionError(
        "should not scan imports"
    )

    results = _make_tools(program).list_imports(query="import", offset=0, limit=0)

    assert results == []
