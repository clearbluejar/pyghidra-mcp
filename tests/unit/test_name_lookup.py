"""Unit tests for name/address resolution in GhidraTools (_lookup_functions, _lookup_symbols).

The symbol-table search itself (``_find_candidate_symbols``) needs a JVM and is mocked
out here. These tests cover the search patterns and what happens to the candidates:
which names match, how jump stubs resolve, ordering, and the full-scan fallback.
"""

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import GhidraTools, _symbol_search_patterns

FUNCTION_TYPE = "Function"
LABEL_TYPE = "Label"


@pytest.fixture(autouse=True)
def fake_symbol_type(monkeypatch):
    """Stand-in for ghidra.program.model.symbol, which needs a running JVM."""
    module = SimpleNamespace(SymbolType=SimpleNamespace(FUNCTION=FUNCTION_TYPE))
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", module)


class TestSearchPatterns:
    def test_exact_simple_name(self):
        assert _symbol_search_patterns("createfilew", partial=False) == ["createfilew"]

    def test_exact_qualified_name_matches_simple_name_by_suffix(self):
        # The simple name can itself contain "::" (templates), so match by suffix.
        assert _symbol_search_patterns("ns::cls::foo", partial=False) == ["*foo"]

    def test_exact_thunk_name_also_searches_its_target(self):
        # Ghidra's search can't see "thunk_FUN_1400"; it is found through FUN_1400.
        assert _symbol_search_patterns("thunk_fun_1400", partial=False) == [
            "thunk_fun_1400",
            "fun_1400",
        ]

    def test_partial_is_a_contains_pattern(self):
        assert _symbol_search_patterns("file", partial=True) == ["*file*"]


class TestFullScanFallback:
    """``_symbol_search_patterns`` returns None when only a full scan is exact."""

    @pytest.mark.parametrize("partial", [False, True])
    @pytest.mark.parametrize("name", ["a*b", "a?b", "a\\b", "café", ""])
    def test_globs_non_ascii_and_empty(self, name, partial):
        assert _symbol_search_patterns(name, partial) is None

    def test_partial_with_colon(self):
        assert _symbol_search_patterns("s::cre", partial=True) is None

    @pytest.mark.parametrize("name", ["thunk", "thunk_fun", "my_thunk"])
    def test_partial_mentioning_thunk(self, name):
        assert _symbol_search_patterns(name, partial=True) is None


def _symbol(name, address, full_name=None, symbol_type=LABEL_TYPE):
    symbol = Mock()
    full_name = full_name or name

    def get_name(include_namespace=False):
        return full_name if include_namespace else name

    symbol.getName.side_effect = get_name
    symbol.getAddress.return_value = address
    symbol.getID.return_value = address
    symbol.getSymbolType.return_value = symbol_type
    return symbol


def _function(name, address, full_name=None, thunk_of=None, external=False):
    func = Mock()
    symbol = _symbol(name, address, full_name, symbol_type=FUNCTION_TYPE)
    symbol.getObject.return_value = func
    func.getSymbol.return_value = symbol
    func.getEntryPoint.return_value = address
    func.getSignature.return_value = f"void {name}(void)"
    func.isThunk.return_value = thunk_of is not None
    func.thunk = thunk_of is not None
    func.getThunkedFunction.return_value = thunk_of
    func.isExternal.return_value = external
    return func


def _tools(functions=(), symbols=(), address_hits=None, name_index=()):
    """GhidraTools over mocks. Names are never addresses unless listed in address_hits.

    ``functions`` with ``external=True`` stand in for imports: the full scan finds them
    through getExternalFunctions(), as Ghidra's getFunctions() never returns them.
    ``name_index`` is what Ghidra's exact-case name index returns; when it is empty,
    lookups fall back to the search.
    """
    tools = GhidraTools.__new__(GhidraTools)
    tools.program_info = Mock()
    tools.program = tools.program_info.program
    tools.decompiler_pool = Mock()

    address_hits = address_hits or {}
    functions = list(functions)
    symbols = list(symbols)
    internal = [f for f in functions if not f.isExternal()]
    external = [f for f in functions if f.isExternal()]

    def get_address(text):
        return text if text in address_hits else None

    def symbols_at(address):
        return [address_hits[address].getSymbol()]

    def find_candidate_symbols(patterns, partial, *, functions_only):
        if functions_only:
            return [f.getSymbol() for f in functions]
        return symbols

    tools.program.getAddressFactory.return_value.getAddress.side_effect = get_address
    function_manager = tools.program.getFunctionManager.return_value
    function_manager.getFunctionAt.side_effect = address_hits.get
    function_manager.getFunctionContaining.return_value = None
    function_manager.getExternalFunctions.return_value = external
    tools.program.getSymbolTable.return_value.getSymbols.side_effect = symbols_at

    tools.get_all_functions = Mock(return_value=internal)
    tools.get_all_symbols = Mock(return_value=symbols)
    tools._find_candidate_symbols = Mock(side_effect=find_candidate_symbols)
    tools._symbols_from_name_index = Mock(return_value=list(name_index))
    return tools


class TestNameIndex:
    """Exact lookups try Ghidra's name index before searching."""

    def test_index_hit_skips_the_search(self):
        target = _function("CreateFileW", 0x10, "KERNEL32.DLL::CreateFileW", external=True)
        tools = _tools(functions=[target], name_index=[target.getSymbol()])
        assert tools.find_function("CreateFileW") is target
        tools._find_candidate_symbols.assert_not_called()

    def test_index_hits_are_checked_against_the_full_name(self):
        a = _function("foo", 0x1000, "A::foo")
        b = _function("foo", 0x2000, "B::foo")
        tools = _tools(functions=[a, b], name_index=[a.getSymbol(), b.getSymbol()])
        assert tools.find_function("B::foo") is b
        tools._find_candidate_symbols.assert_not_called()

    def test_index_hit_on_a_stub_resolves_to_its_target(self):
        target = _function("printf", 0x10, "LIBC::printf", external=True)
        stub = _function("printf", 0x1000, "LIBC::printf", thunk_of=target)
        tools = _tools(functions=[stub, target], name_index=[stub.getSymbol()])
        assert tools.find_function("printf") is target

    def test_exact_case_wins_over_other_spellings(self):
        # The index only finds "foo"; "Foo" would make the search ambiguous.
        lower = _function("foo", 0x1000)
        upper = _function("Foo", 0x2000)
        tools = _tools(functions=[lower, upper], name_index=[lower.getSymbol()])
        assert tools.find_function("foo") is lower

    def test_index_miss_falls_back_to_the_search(self):
        target = _function("CreateFileW", 0x10, "KERNEL32.DLL::CreateFileW", external=True)
        tools = _tools(functions=[target])
        assert tools.find_function("createfilew") is target
        tools._find_candidate_symbols.assert_called_once()

    def test_partial_lookups_never_use_the_index(self):
        func = _function("main", 0x1000)
        tools = _tools(functions=[func], name_index=[func.getSymbol()])
        assert tools.find_functions("main") == [func]
        tools._symbols_from_name_index.assert_not_called()

    def test_symbol_index_hit_skips_the_search(self):
        label = _symbol("start", 0x1000)
        tools = _tools(symbols=[label], name_index=[label])
        assert tools.find_symbol("start") is label
        tools._find_candidate_symbols.assert_not_called()

    def test_index_is_asked_for_the_last_part_in_its_original_case(self):
        tools = GhidraTools.__new__(GhidraTools)
        tools.program = Mock()
        func = _function("Foo", 0x1000, "Ns::Foo")
        symbol_table = tools.program.getSymbolTable.return_value
        symbol_table.getSymbols.return_value = [func.getSymbol()]
        assert tools._symbols_from_name_index("Ns::Foo", functions_only=True) == [func.getSymbol()]
        symbol_table.getSymbols.assert_called_once_with("Foo")


class TestFindFunction:
    def test_address_is_tried_first(self):
        func = _function("main", 0x1000)
        tools = _tools(functions=[_function("0x1000", 0x2000)], address_hits={"0x1000": func})
        assert tools.find_function("0x1000") is func
        tools._find_candidate_symbols.assert_not_called()

    def test_address_of_a_stub_returns_the_stub(self):
        target = _function("CreateFileW", 0x10, "KERNEL32.DLL::CreateFileW", external=True)
        stub = _function("CreateFileW", 0x1000, "KERNEL32.DLL::CreateFileW", thunk_of=target)
        tools = _tools(functions=[stub, target], address_hits={"0x1000": stub})
        assert tools.find_function("0x1000") is stub

    @pytest.mark.parametrize("name", ["CreateFileW", "createfilew", "kernel32.dll::CREATEFILEW"])
    def test_import_by_simple_or_full_name(self, name):
        target = _function("CreateFileW", 0x10, "KERNEL32.DLL::CreateFileW", external=True)
        tools = _tools(functions=[target])
        assert tools.find_function(name) is target

    def test_stubs_named_after_their_target_resolve_to_it(self):
        # Two jump stubs and the import all share a name: one function, not ambiguous.
        target = _function("_o_free", 0x10, "CRT.DLL::_o_free", external=True)
        stub_a = _function("_o_free", 0x1000, "CRT.DLL::_o_free", thunk_of=target)
        stub_b = _function("_o_free", 0x2000, "CRT.DLL::_o_free", thunk_of=target)
        tools = _tools(functions=[stub_a, stub_b, target])
        assert tools.find_function("_o_free") is target

    def test_stub_resolves_even_when_its_target_was_not_a_candidate(self):
        target = _function("printf", 0x10, "LIBC::printf", external=True)
        stub = _function("printf", 0x1000, thunk_of=target)
        tools = _tools(functions=[stub])
        assert tools.find_function("printf") is target

    def test_thunk_with_its_own_name_is_returned_as_itself(self):
        target = _function("FUN_1400", 0x1400)
        thunk = _function("thunk_FUN_1400", 0x2000, thunk_of=target)
        tools = _tools(functions=[target, thunk])
        assert tools.find_function("thunk_FUN_1400") is thunk
        assert tools.find_function("FUN_1400") is target

    def test_same_simple_name_in_two_namespaces_is_ambiguous(self):
        a = _function("foo", 0x1000, "A::foo")
        b = _function("foo", 0x2000, "B::foo")
        tools = _tools(functions=[b, a])
        with pytest.raises(ValueError, match=r"Ambiguous match for 'foo'.*A::foo.*B::foo"):
            tools.find_function("foo")
        assert tools.find_function("b::foo") is b

    def test_not_found(self):
        tools = _tools(functions=[_function("main", 0x1000)])
        with pytest.raises(ValueError, match="not found"):
            tools.find_function("nope")

    def test_full_scan_includes_imports(self):
        target = _function("a*b", 0x10, "LIB::a*b", external=True)
        tools = _tools(functions=[target])
        assert tools.find_function("a*b") is target
        tools._find_candidate_symbols.assert_not_called()


class TestFindFunctions:
    def test_exact_matches_come_before_partial_matches(self):
        long_a = _function("main_loop", 0x1000)
        exact = _function("main", 0x3000)
        long_b = _function("_main", 0x2000)
        tools = _tools(functions=[long_a, exact, long_b])
        assert tools.find_functions("main") == [exact, long_a, long_b]

    def test_lists_stubs_and_leaves_out_imports(self):
        target = _function("printf", 0x10, "LIBC::printf", external=True)
        stub = _function("printf", 0x1000, "LIBC::printf", thunk_of=target)
        body = _function("my_printf", 0x2000)
        tools = _tools(functions=[stub, target, body])
        assert tools.find_functions("printf") == [stub, body]

    def test_not_found(self):
        tools = _tools(functions=[_function("main", 0x1000)])
        assert tools.find_functions("nope") == []


class TestLookupSymbols:
    def test_exact_before_partial_and_sorted(self):
        exact = _symbol("foo", 0x3000)
        longer = _symbol("foobar", 0x1000)
        other = _symbol("barfoo", 0x2000)
        tools = _tools(symbols=[other, exact, longer])
        assert tools._lookup_symbols("FOO", partial=True) == [exact, longer, other]
        assert tools._lookup_symbols("FOO") == [exact]

    def test_import_and_its_stub_resolve_to_one_symbol(self):
        target = _function("CreateFileW", 0x10, "KERNEL32.DLL::CreateFileW", external=True)
        stub = _function("CreateFileW", 0x1000, "KERNEL32.DLL::CreateFileW", thunk_of=target)
        tools = _tools(symbols=[stub.getSymbol(), target.getSymbol()])
        assert tools.find_symbol("CreateFileW") is target.getSymbol()

    def test_ambiguous_symbol(self):
        tools = _tools(symbols=[_symbol("dup", 0x1000), _symbol("dup", 0x2000)])
        with pytest.raises(ValueError, match="Ambiguous match for 'dup'"):
            tools.find_symbol("dup")

    def test_dynamic_scans_dynamic_symbols(self):
        named = _symbol("lab_target", 0x1000)
        dynamic = _symbol("LAB_00401000", 0x401000)

        def get_all_symbols(include_externals=False, include_dynamic=False):
            return [named, dynamic] if include_dynamic else [named]

        tools = _tools(symbols=[named])
        tools.get_all_symbols = Mock(side_effect=get_all_symbols)
        assert tools._lookup_symbols("lab_", dynamic=True) == [named, dynamic]
        tools._find_candidate_symbols.assert_not_called()
