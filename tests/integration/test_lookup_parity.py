"""Parity: the symbol-table name lookup against the full-scan implementation it replaced.

``_lookup_functions`` / ``_lookup_symbols`` used to walk every function or symbol in
Python. They now let ``SymbolTable.getSymbolIterator`` filter names in Java and add
back what it skips (default thunks, namespace-path matches). This test keeps the old
scan as the reference and checks the new lookup returns the same matches for queries
drawn from a real analyzed program.

The old scan returned matches in set order, so the reference is compared group by
group: exact matches first, then partial matches, each sorted by address and then
symbol ID (the order the new lookup guarantees).

Binary: ``PYGHIDRA_MCP_PARITY_BINARY`` if set, else ``C:/Windows/System32/notepad.exe``
on Windows, else a small binary compiled with gcc. Needs ``GHIDRA_INSTALL_DIR``.
"""

import os
import random
import shutil
import subprocess
import warnings
from pathlib import Path
from unittest.mock import Mock

import pytest

from pyghidra_mcp.tools import GhidraTools

_C_SOURCE = """
#include <stdio.h>
void function_one() { printf("Function One"); }
void function_two() { printf("Function Two"); }
int main() { printf("Hello"); function_one(); function_two(); return 0; }
"""


def _parity_binary(tmp_path_factory) -> Path:
    configured = os.environ.get("PYGHIDRA_MCP_PARITY_BINARY")
    if configured:
        return Path(configured)
    notepad = Path("C:/Windows/System32/notepad.exe")
    if notepad.is_file():
        return notepad
    if shutil.which("gcc") is None:
        pytest.skip("no parity binary: set PYGHIDRA_MCP_PARITY_BINARY or install gcc")
    build = tmp_path_factory.mktemp("parity-bin")
    source = build / "parity.c"
    source.write_text(_C_SOURCE)
    binary = build / "parity"
    subprocess.run(["gcc", "-o", str(binary), str(source)], check=True)
    return binary


@pytest.fixture(scope="module")
def tools(tmp_path_factory, ghidra_env):
    binary = _parity_binary(tmp_path_factory)
    if not binary.is_file():
        pytest.skip(f"parity binary not found: {binary}")

    import pyghidra

    pyghidra.start()
    project = tmp_path_factory.mktemp("parity-project")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pyghidra.open_program(
            binary, project_location=project, project_name="parity", analyze=True
        ) as flat_api:
            program_info = Mock()
            program_info.program = flat_api.getCurrentProgram()
            yield GhidraTools(program_info)


def _entry(func):
    return func.getEntryPoint()


def _address(symbol):
    return (symbol.getAddress(), int(symbol.getID()))


class _Reference:
    """The pre-change implementation, over lists materialized once (the program
    doesn't change during the test, so this is the same as rescanning per query)."""

    def __init__(self, tools: GhidraTools):
        self.tools = tools
        self.functions = {
            include: [
                (f, str(f.getSymbol().getName(True)).lower())
                for f in tools.get_all_functions(include_externals=include)
            ]
            for include in (True, False)
        }
        self.symbols = [
            (s, str(s.getName(True)).lower()) for s in tools.get_all_symbols(include_externals=True)
        ]

    def lookup_functions(self, name: str, partial: bool, include_externals: bool):
        name_lc = name.lower()
        pairs = self.functions[include_externals]
        exact = [f for f, q in pairs if q == name_lc]
        rest = [f for f, q in pairs if partial and q != name_lc and name_lc in q]
        return sorted(exact, key=_entry) + sorted(rest, key=_entry)

    def lookup_symbols(self, name: str, partial: bool):
        name_lc = name.lower()
        exact = [s for s, q in self.symbols if q == name_lc]
        rest = [s for s, q in self.symbols if partial and q != name_lc and name_lc in q]
        return sorted(exact, key=_address) + sorted(rest, key=_address)


@pytest.fixture(scope="module")
def reference(tools):
    return _Reference(tools)


def _swap_case(text: str) -> str:
    return text.swapcase() if text.swapcase() != text else text.upper()


@pytest.fixture(scope="module")
def name_queries(tools, reference):
    """Names drawn from the program: exact, other-case, qualified, thunks, FUN_ and
    thunk_FUN_ names, duplicates, substrings (some starting inside 'thunk_'),
    namespace names, and names that don't exist."""
    from ghidra.program.model.symbol import SymbolType

    rng = random.Random(0)
    symbol_names = sorted({str(s.getName(True)) for s, _ in reference.symbols})
    function_names = sorted(
        {str(f.getSymbol().getName(True)) for f, _ in reference.functions[True]}
    )
    thunk_names = sorted(
        {str(f.getSymbol().getName(True)) for f, _ in reference.functions[True] if f.isThunk()}
    )
    # Namespaces, classes and libraries have no address, so getAllSymbols() (and the
    # reference) never returns them; their names still match through descendants.
    namespace_names = sorted(
        {
            str(s.getName())
            for s in tools.program.getSymbolTable().getSymbolIterator("*", False)
            if s.getSymbolType().isNamespace() and s.getSymbolType() != SymbolType.FUNCTION
        }
    )
    qualified = [n for n in symbol_names if "::" in n]

    queries = set()
    for pool, count in (
        (function_names, 60),
        (thunk_names, 20),
        (symbol_names, 60),
        (qualified, 30),
        (namespace_names, 10),
    ):
        queries.update(rng.sample(pool, min(count, len(pool))))
    queries.update(_swap_case(q) for q in sorted(queries)[:40])
    substring_sources = function_names + symbol_names + namespace_names
    for name in rng.sample(substring_sources, min(80, len(substring_sources))):
        simple = name.rsplit("::", 1)[-1]
        if len(simple) > 4:
            start = rng.randrange(0, len(simple) - 3)
            queries.add(simple[start : start + rng.randrange(3, 7)])
    queries.update(n.rsplit("::", 1)[-1] for n in qualified[:20])
    queries.update(
        {"main", "MAIN", "entry", "FUN_", "thunk_", "unk_F", "k_FUN_", "_", "no_such_name_xyz"}
    )
    return sorted(q for q in queries if q)


def _ids(items):
    return [str(i) for i in items]


def test_queries_cover_the_interesting_cases(reference, name_queries):
    """Guard against a binary too small to exercise the lookup."""
    assert len(name_queries) > 20
    assert any(f.isThunk() for f, _ in reference.functions[True]), "no thunks in binary"


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("include_externals", [True, False])
def test_function_lookup_matches_scan(tools, reference, name_queries, partial, include_externals):
    mismatches = []
    for query in name_queries:
        expected = reference.lookup_functions(query, partial, include_externals)
        actual = tools._lookup_functions(
            query, partial=partial, include_externals=include_externals
        )
        if _ids(actual) != _ids(expected):
            mismatches.append((query, _ids(expected)[:5], _ids(actual)[:5]))
    assert not mismatches, mismatches[:10]


@pytest.mark.parametrize("partial", [False, True])
def test_symbol_lookup_matches_scan(tools, reference, name_queries, partial):
    mismatches = []
    for query in name_queries:
        expected = reference.lookup_symbols(query, partial)
        actual = tools._lookup_symbols(query, partial=partial)
        if [int(s.getID()) for s in actual] != [int(s.getID()) for s in expected]:
            mismatches.append((query, _ids(expected)[:5], _ids(actual)[:5]))
    assert not mismatches, mismatches[:10]


def test_ambiguous_name_raises(tools, reference):
    counts: dict[str, int] = {}
    for _, qualified in reference.functions[True]:
        counts[qualified] = counts.get(qualified, 0) + 1
    duplicated = sorted(q for q, n in counts.items() if n > 1)
    if not duplicated:
        pytest.skip("binary has no duplicate function names")
    with pytest.raises(ValueError, match="Ambiguous match"):
        tools.find_function(duplicated[0])


def test_address_lookups_resolve_first(tools, reference):
    for func, _ in reference.functions[False][:20]:
        entry = func.getEntryPoint()
        assert _ids(tools._lookup_functions(str(entry))) == [str(func)]
        body = func.getBody()
        if body.getNumAddresses() > 1:
            inside = body.getMaxAddress()
            assert _ids(tools._lookup_functions(str(inside))) == [str(func)]
        expected = [int(s.getID()) for s in tools.program.getSymbolTable().getSymbols(entry)]
        assert [int(s.getID()) for s in tools._lookup_symbols(str(entry))] == expected


def test_nonexistent_name(tools):
    with pytest.raises(ValueError, match="not found"):
        tools.find_function("no_such_name_xyz")
    assert tools.find_functions("no_such_name_xyz") == []
    assert tools.find_symbols("no_such_name_xyz") == []


@pytest.mark.parametrize("functions_only", [False, True])
def test_search_symbols_by_name_matches_scan(tools, reference, name_queries, functions_only):
    """Plain queries go through find_functions / find_symbols; regex and invalid regex
    still scan. Ranking and pagination must not change."""
    baseline = GhidraTools(tools.program_info)
    baseline.find_functions = lambda q, include_externals=True: reference.lookup_functions(
        q, True, include_externals
    )
    baseline.find_symbols = lambda q: reference.lookup_symbols(q, True)

    queries = [*name_queries[::5], "^main$", "fun.*_", "[invalid", "(unclosed"]
    mismatches = []
    for query in queries:
        expected = baseline.search_symbols_by_name(query, functions_only=functions_only)
        actual = tools.search_symbols_by_name(query, functions_only=functions_only)
        if actual != expected:
            mismatches.append(query)
    assert not mismatches, mismatches[:10]
