"""Unit tests for name/address resolution in GhidraTools (_lookup_functions, _lookup_symbols).

The symbol-table search itself (``_name_candidates``) needs a JVM; its parity with the
old full scan is checked in tests/integration/test_lookup_parity.py. These tests cover
the pattern rules and the behavior around it with mocks.
"""

from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import GhidraTools, _name_lookup_needs_scan, _name_patterns


class TestNamePatterns:
    def test_exact_simple_name(self):
        assert _name_patterns("createfilew", partial=False) == ["createfilew"]

    def test_exact_qualified_name_matches_simple_name_by_suffix(self):
        # The simple name can itself contain "::" (templates), so match by suffix.
        assert _name_patterns("ns::cls::foo", partial=False) == ["*foo"]

    def test_exact_thunk_name_also_searches_its_target(self):
        assert _name_patterns("thunk_fun_1400", partial=False) == [
            "thunk_fun_1400",
            "fun_1400",
        ]

    def test_partial_is_a_contains_pattern(self):
        assert _name_patterns("file", partial=True) == ["*file*"]

    def test_partial_starting_inside_thunk_prefix_searches_target_prefix(self):
        # "_fun_14" can match "thunk_FUN_1400" across the prefix.
        assert _name_patterns("_fun_14", partial=True) == ["*_fun_14*", "fun_14*"]
        assert _name_patterns("unk_fun", partial=True) == ["*unk_fun*", "fun*"]
        assert _name_patterns("thunk_fun", partial=True) == ["*thunk_fun*", "fun*"]


class TestNeedsScan:
    @pytest.mark.parametrize("partial", [False, True])
    def test_plain_names_use_the_symbol_table(self, partial):
        assert not _name_lookup_needs_scan("createfilew", partial)

    def test_exact_qualified_names_use_the_symbol_table(self):
        assert not _name_lookup_needs_scan("kernel32.dll::createfilew", partial=False)

    def test_partial_with_colon_scans(self):
        assert _name_lookup_needs_scan("s::cre", partial=True)

    @pytest.mark.parametrize("name", ["a*b", "a?b", "a\\b"])
    def test_glob_characters_scan(self, name):
        assert _name_lookup_needs_scan(name, partial=False)

    def test_non_ascii_scans(self):
        assert _name_lookup_needs_scan("café", partial=False)

    def test_empty_scans(self):
        assert _name_lookup_needs_scan("", partial=True)

    @pytest.mark.parametrize("name", ["_", "thunk", "unk_", "thunk_"])
    def test_partial_inside_thunk_prefix_scans(self, name):
        assert _name_lookup_needs_scan(name, partial=True)


def _symbol(name, address, qualified=None, sym_id=None):
    sym = Mock()
    sym.getName.side_effect = lambda include_namespace=False: (
        (qualified or name) if include_namespace else name
    )
    sym.getAddress.return_value = address
    sym.getID.return_value = sym_id if sym_id is not None else address
    return sym


def _function(name, address, qualified=None, thunk=False, external=False):
    func = Mock()
    func.getSymbol.return_value = _symbol(name, address, qualified)
    func.getSymbol.return_value.getObject.return_value = func
    func.getEntryPoint.return_value = address
    func.getSignature.return_value = f"void {name}(void)"
    func.isThunk.return_value = thunk
    func.thunk = thunk
    func.isExternal.return_value = external
    return func


def _tools(functions=(), symbols=(), address_hits=None):
    """GhidraTools over mocks. Names are never addresses unless listed in address_hits."""
    tools = GhidraTools.__new__(GhidraTools)
    tools.program_info = Mock()
    tools.program = tools.program_info.program
    tools.decompiler_pool = Mock()

    address_hits = address_hits or {}
    af = tools.program.getAddressFactory.return_value
    af.getAddress.side_effect = lambda text: text if text in address_hits else None
    fm = tools.program.getFunctionManager.return_value
    fm.getFunctionAt.side_effect = lambda addr: address_hits.get(addr)
    fm.getFunctionContaining.return_value = None
    st = tools.program.getSymbolTable.return_value
    st.getSymbols.side_effect = lambda addr: [address_hits[addr].getSymbol()]

    functions = list(functions)
    symbols = list(symbols)

    def get_all_functions(include_externals=False):
        return [f for f in functions if include_externals or not f.thunk]

    def name_candidates(name_lc, partial, *, functions_only):
        if functions_only:
            return [f.getSymbol() for f in functions]
        return symbols

    tools.get_all_functions = Mock(side_effect=get_all_functions)
    tools.get_all_symbols = Mock(return_value=symbols)
    tools._name_candidates = Mock(side_effect=name_candidates)
    return tools


class TestLookupFunctions:
    def test_address_is_tried_first(self):
        func = _function("main", 0x1000)
        tools = _tools(functions=[_function("0x1000", 0x2000)], address_hits={"0x1000": func})
        assert tools._lookup_functions("0x1000") == [func]
        tools._name_candidates.assert_not_called()

    def test_exact_match_ignores_case_and_compares_qualified_name(self):
        foo = _function("foo", 0x1000, qualified="Ns::foo")
        tools = _tools(functions=[foo, _function("foo", 0x2000)])
        assert tools._lookup_functions("ns::FOO") == [foo]

    def test_simple_name_does_not_exactly_match_namespaced_function(self):
        tools = _tools(functions=[_function("foo", 0x1000, qualified="Ns::foo")])
        assert tools._lookup_functions("foo") == []

    def test_exact_matches_come_before_partial_matches(self):
        long_a = _function("main_loop", 0x1000)
        exact = _function("main", 0x3000)
        long_b = _function("_main", 0x2000)
        tools = _tools(functions=[long_a, exact, long_b])
        assert tools._lookup_functions("main", partial=True) == [exact, long_a, long_b]

    def test_include_externals_false_drops_thunks(self):
        body = _function("printf", 0x2000)
        thunk = _function("printf", 0x1000, thunk=True)
        tools = _tools(functions=[thunk, body])
        assert tools._lookup_functions("printf", include_externals=False) == [body]
        assert tools._lookup_functions("printf") == [thunk, body]

    def test_external_functions_are_never_returned(self):
        ext = _function("printf", 0x10, qualified="printf", external=True)
        tools = _tools(functions=[ext])
        assert tools._lookup_functions("printf") == []

    def test_ambiguous_name_lists_each_match(self):
        tools = _tools(functions=[_function("dup", 0x1000), _function("dup", 0x2000)])
        with pytest.raises(ValueError, match=r"Ambiguous match for 'dup'.*dup\(void dup\(void\)\)"):
            tools.find_function("dup")

    def test_not_found(self):
        tools = _tools(functions=[_function("main", 0x1000)])
        with pytest.raises(ValueError, match="not found"):
            tools.find_function("nope")
        assert tools.find_functions("nope") == []

    def test_scan_fallback_has_the_same_ordering(self):
        exact = _function("a*b", 0x3000)
        longer = _function("xa*b", 0x1000)
        tools = _tools(functions=[exact, longer])
        assert tools._lookup_functions("A*B", partial=True) == [exact, longer]
        tools._name_candidates.assert_not_called()


class TestLookupSymbols:
    def test_exact_before_partial_and_sorted(self):
        exact = _symbol("foo", 0x3000)
        longer = _symbol("foobar", 0x1000)
        other = _symbol("barfoo", 0x2000)
        tools = _tools(symbols=[other, exact, longer])
        assert tools._lookup_symbols("FOO", partial=True) == [exact, longer, other]
        assert tools._lookup_symbols("FOO") == [exact]

    def test_ambiguous_symbol(self):
        tools = _tools(symbols=[_symbol("dup", 0x1000), _symbol("dup", 0x2000)])
        with pytest.raises(ValueError, match="Ambiguous match for 'dup'"):
            tools.find_symbol("dup")

    def test_dynamic_scans_dynamic_symbols(self):
        named = _symbol("lab_target", 0x1000)
        dynamic = _symbol("LAB_00401000", 0x401000)

        tools = _tools(symbols=[named])
        tools.get_all_symbols = Mock(
            side_effect=lambda include_externals=False, include_dynamic=False: (
                [named, dynamic] if include_dynamic else [named]
            )
        )
        assert tools._lookup_symbols("lab_", dynamic=True) == [named, dynamic]
        tools._name_candidates.assert_not_called()
