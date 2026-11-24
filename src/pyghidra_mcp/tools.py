"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import logging
import math
import re
import time
import typing
from contextlib import contextmanager

from ghidrecomp.callgraph import gen_callgraph
from jpype import JByte

from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResult,
    CodeSearchResults,
    CrossReferenceInfo,
    DecompiledFunction,
    DisassembleResult,
    ExportInfo,
    ImportInfo,
    SearchMode,
    StringInfo,
    StringSearchResult,
    SymbolInfo,
)

_REGEX_META = re.compile(r"[\\^$.|?*+(){}\[\]]")


def _symbol_search_patterns(name: str, partial: bool) -> list[str] | None:
    """Build the patterns to pass to ``SymbolTable.getSymbolIterator`` for a name lookup.

    ``name`` is the lower-cased name being looked up. The patterns are matched
    case-insensitively against each symbol's simple name (``foo``, not ``Ns::foo``) and
    may find extra symbols; the caller checks the full name of every hit.

    Returns None when this search could miss a match, so the caller must check every
    symbol instead.
    """
    if not name:
        return None
    # Java only ignores case for ASCII letters.
    if not name.isascii():
        return None
    # The pattern language uses * and ? as wildcards and \ as an escape.
    if "*" in name or "?" in name or "\\" in name:
        return None

    if partial:
        # Text with ':' can match across the "::" between a namespace and a name.
        if ":" in name:
            return None
        # The search can't see thunks Ghidra named "thunk_FUN_1234", so text that
        # mentions them needs a full scan.
        if "thunk" in name:
            return None
        return [f"*{name}*"]

    if "::" in name:
        # "ns::foo": search for simple names ending in "foo". A simple name can contain
        # "::" itself (template arguments), so it can be longer than the last part.
        last_part = name.split("::")[-1]
        pattern = "*" + last_part
    else:
        last_part = name
        pattern = name
    patterns = [pattern]
    # The search can't see thunks Ghidra named "thunk_FUN_1234", so search for FUN_1234
    # instead; _find_candidate_symbols adds its thunks back.
    if last_part.startswith("thunk_"):
        patterns.append(pattern.replace("thunk_", "", 1))
    return patterns


def _matches_exactly(symbol, name: str) -> bool:
    """True if ``name`` is the symbol's simple name (``CreateFileW``) or its full name
    (``KERNEL32.DLL::CreateFileW``), ignoring case."""
    return symbol.getName().lower() == name or symbol.getName(True).lower() == name


def _keep_lookup_kinds(symbols: typing.Iterable, functions_only: bool) -> list:
    """Keep function symbols, or with ``functions_only`` unset, the symbols
    getAllSymbols() would list: it skips variables and namespaces, which have no memory
    address."""
    from ghidra.program.model.symbol import SymbolType

    results = []
    for symbol in symbols:
        if functions_only:
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                results.append(symbol)
            continue
        address = symbol.getAddress()
        if address.isMemoryAddress() or address.isExternalAddress():
            results.append(symbol)
    return results


def _address_then_id(symbol) -> tuple:
    # Several symbols can share an address, so the ID keeps the order stable.
    return (symbol.getAddress(), int(symbol.getID()))


def _filter_and_sort_matches(symbols: typing.Iterable, name: str, partial: bool) -> list:
    """Keep the symbols that match ``name`` exactly, or whose full name contains it when
    ``partial`` is set. Exact matches come first; each group is sorted by address."""
    exact_matches = []
    partial_matches = []
    for symbol in symbols:
        if _matches_exactly(symbol, name):
            exact_matches.append(symbol)
        elif partial and name in symbol.getName(True).lower():
            partial_matches.append(symbol)
    exact_matches.sort(key=_address_then_id)
    partial_matches.sort(key=_address_then_id)
    return exact_matches + partial_matches


if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo

logger = logging.getLogger(__name__)
DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 30


@contextmanager
def ghidra_transaction(program, description: str):
    tx_id = program.startTransaction(description)
    committed = False
    try:
        yield
        committed = True
    finally:
        program.endTransaction(tx_id, committed)


def handle_exceptions(func):
    """Decorator to handle exceptions in tool methods"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """Comprehensive tool handler for Ghidra MCP tools"""

    def __init__(self, program_info: "ProgramInfo"):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler_pool = program_info.decompiler_pool

    def _get_filename(self, func: "Function"):
        max_path_len = 50
        return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"

    def _resolve_function_variable(
        self,
        function_name_or_address: str,
        variable_name: str,
    ) -> tuple["Function", str, typing.Any]:
        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())

        matches: list[tuple[str, typing.Any]] = []
        for param in func.getParameters():
            if str(param.getName()) == variable_name:
                matches.append(("parameter", param))
        for local in func.getLocalVariables():
            if str(local.getName()) == variable_name:
                matches.append(("local", local))

        if not matches:
            raise ValueError(f"Variable '{variable_name}' not found in function '{function_name}'.")
        if len(matches) > 1:
            kinds = ", ".join(kind for kind, _ in matches)
            raise ValueError(
                f"Ambiguous variable '{variable_name}' in function '{function_name}' ({kinds})."
            )

        variable_kind, variable = matches[0]
        return func, variable_kind, variable

    def _parse_data_type(self, type_name: str):
        from ghidra.util.data import DataTypeParser  # type: ignore
        from ghidra.util.data.DataTypeParser import AllowedDataTypes  # type: ignore

        dtm = self.program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, typing.cast(typing.Any, None), AllowedDataTypes.DYNAMIC)
        return parser.parse(type_name)

    def _lookup_functions(self, name_or_address: str, partial: bool = False) -> list["Function"]:
        """
        Resolve functions by address, or by name ignoring case.

        Exact lookups match the simple name (``CreateFileW``) or the full name
        (``KERNEL32.DLL::CreateFileW``). They include imported functions and return the
        real function rather than a jump stub named after it (see
        ``_replace_stubs_with_targets``). Results are sorted by address.

        Partial lookups (substring of the full name) are for listing: they return exact
        matches first, include stubs, and leave out imported functions.
        """
        func = self._function_at_address(name_or_address)
        if func is not None:
            return [func]

        name = name_or_address.lower()
        matches = []
        if not partial:
            indexed = self._symbols_from_name_index(name_or_address, functions_only=True)
            matches = _filter_and_sort_matches(indexed, name, partial)
        if not matches:
            candidates = self._function_candidates(name, partial)
            matches = _filter_and_sort_matches(candidates, name, partial)
        if not partial:
            matches = self._replace_stubs_with_targets(matches, name)

        functions = []
        for symbol in matches:
            func = symbol.getObject()
            if partial and func.isExternal():
                continue
            functions.append(func)
        return functions

    def _function_candidates(self, name: str, partial: bool) -> list["Symbol"]:
        """Function symbols that might match ``name``; the caller checks each one."""
        # The symbol table can only search simple names (foo, not ns::foo), so the
        # patterns find every symbol that might match, plus some that don't.
        patterns = _symbol_search_patterns(name, partial)
        if patterns is not None:
            return self._find_candidate_symbols(patterns, partial, functions_only=True)
        candidates = []
        for func in self.get_all_functions(include_externals=True):
            candidates.append(func.getSymbol())
        for func in self.program.getFunctionManager().getExternalFunctions():
            candidates.append(func.getSymbol())
        return candidates

    def _symbols_from_name_index(
        self, name_or_address: str, *, functions_only: bool
    ) -> list["Symbol"]:
        """Symbols whose simple name is exactly the last part of ``name_or_address``,
        case included, from Ghidra's name index. One call instead of a search, but it
        misses other spellings of the case and auto-named thunks, so callers fall back to
        a search when it finds no match."""
        simple_name = name_or_address.split("::")[-1]
        symbols = self.program.getSymbolTable().getSymbols(simple_name)
        return _keep_lookup_kinds(symbols, functions_only)

    def _function_at_address(self, text: str) -> "Function | None":
        """The function at or containing ``text`` read as an address, if any."""
        fm = self.program.getFunctionManager()
        try:
            addr = self.program.getAddressFactory().getAddress(text)
        except Exception as e:
            logger.debug(f"'{text}' is not an address ({e}); searching by name")
            return None
        if not addr:
            return None
        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
        return func

    def _replace_stubs_with_targets(self, symbols: list["Symbol"], name: str) -> list["Symbol"]:
        """Replace each thunk that carries the looked-up name of the function it jumps to
        (an import's jump stub, say) with that function, so that a name means the real
        function. A thunk with a name of its own, such as ``thunk_FUN_1234``, stays."""
        from ghidra.program.model.symbol import SymbolType

        results: dict[int, Symbol] = {}
        for symbol in symbols:
            if symbol.getSymbolType() == SymbolType.FUNCTION and symbol.getObject().isThunk():
                target = symbol.getObject().getThunkedFunction(True)
                if target is not None and _matches_exactly(target.getSymbol(), name):
                    symbol = target.getSymbol()
            results[int(symbol.getID())] = symbol
        return sorted(results.values(), key=_address_then_id)

    def _find_candidate_symbols(
        self, patterns: list[str], partial: bool, *, functions_only: bool
    ) -> list["Symbol"]:
        """Find every symbol that might match a name lookup, without walking the whole
        symbol table in Python. The caller checks each one's full name.

        ``getSymbolIterator`` does the matching in Java, so only its hits cross into
        Python. It misses two kinds of match, which are added here:

        * Thunks that Ghidra named after their target. The iterator never returns them.
          They share their target's name (or ``thunk_`` + it) and namespace, so they are
          found by asking each function found for its thunks.
        * Partial matches on a namespace (``Ns`` matching ``Ns::foo``). Everything
          inside a matching namespace is added.
        """
        symbol_table = self.program.getSymbolTable()
        found: dict[int, Symbol] = {}
        to_visit: list[Symbol] = []
        for pattern in patterns:
            to_visit.extend(symbol_table.getSymbolIterator(pattern, False))

        while to_visit:
            symbol = to_visit.pop()
            symbol_id = int(symbol.getID())
            if symbol_id in found:
                continue
            found[symbol_id] = symbol
            to_visit.extend(self._symbols_named_after(symbol, partial, functions_only))
        return _keep_lookup_kinds(found.values(), functions_only)

    def _symbols_named_after(
        self, symbol: "Symbol", partial: bool, functions_only: bool
    ) -> list["Symbol"]:
        """Symbols whose full name is built from ``symbol``'s name, so they can match
        whenever it does: a function's thunks, and for partial lookups everything inside
        a namespace."""
        from ghidra.program.model.symbol import SymbolType

        related = []
        is_function = symbol.getSymbolType() == SymbolType.FUNCTION
        if is_function:
            function_manager = self.program.getFunctionManager()
            for address in symbol.getObject().getFunctionThunkAddresses(True) or []:
                related.append(function_manager.getFunctionAt(address).getSymbol())

        if not partial or not symbol.getSymbolType().isNamespace():
            return related
        # Functions can't be nested in functions, so when we only want functions there
        # is no need to look at a function's parameters and locals.
        if functions_only and is_function:
            return related
        related.extend(self.program.getSymbolTable().getChildren(symbol))
        return related

    @handle_exceptions
    def find_function(self, name_or_address: str) -> "Function":
        """
        Resolve a single function by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_functions(name_or_address, partial=False)

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [
                f"{f.getSymbol().getName(True)}({f.getSignature()}) @ {f.getEntryPoint()}"
                for f in matches
            ]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Function or symbol '{name_or_address}' not found.")

    @handle_exceptions
    def find_functions(self, name_or_address: str) -> list["Function"]:
        """
        Return all functions that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_functions(name_or_address, partial=True)

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        partial: bool = False,
        dynamic: bool = False,
    ) -> list["Symbol"]:
        """
        Resolve symbols by address, or by name ignoring case.

        Exact lookups match the simple or the full name, and return the real function
        rather than a jump stub named after it, as ``_lookup_functions`` does. Partial
        lookups (substring of the full name) return exact matches first. ``dynamic``
        also matches substrings of dynamic symbols (``LAB_``, ``DAT_``...), which needs
        a full scan.
        """
        st = self.program.getSymbolTable()
        af = self.program.getAddressFactory()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                addr_symbols = st.getSymbols(addr)
                if addr_symbols:
                    return list(addr_symbols)
        except Exception as e:
            logger.debug(f"'{name_or_address}' is not an address ({e}); searching by name")

        name = name_or_address.lower()
        if dynamic:
            # Dynamic symbols (LAB_, DAT_...) aren't stored, so only a full scan finds
            # them. A dynamic lookup always matches substrings.
            candidates = self.get_all_symbols(include_externals=True, include_dynamic=True)
            return _filter_and_sort_matches(candidates, name, partial=True)

        if partial:
            return _filter_and_sort_matches(self._symbol_candidates(name, partial), name, True)
        indexed = self._symbols_from_name_index(name_or_address, functions_only=False)
        matches = _filter_and_sort_matches(indexed, name, partial)
        if not matches:
            candidates = self._symbol_candidates(name, partial)
            matches = _filter_and_sort_matches(candidates, name, partial)
        return self._replace_stubs_with_targets(matches, name)

    def _symbol_candidates(self, name: str, partial: bool) -> list["Symbol"]:
        """Symbols that might match ``name``; the caller checks each one."""
        # The symbol table can only search simple names (foo, not ns::foo), so the
        # patterns find every symbol that might match, plus some that don't.
        patterns = _symbol_search_patterns(name, partial)
        if patterns is None:
            return list(self.get_all_symbols(include_externals=True))
        return self._find_candidate_symbols(patterns, partial, functions_only=False)

    @handle_exceptions
    def find_symbols(self, name_or_address: str) -> list["Symbol"]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """
        Resolve a single symbol by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, partial=False)

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [f"{s.getName(True)} @ {s.getAddress()}" for s in matches]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Symbol '{name_or_address}' not found.")

    @handle_exceptions
    def decompile_function_by_name_or_addr(
        self, name_or_address: str, timeout: int = DEFAULT_DECOMPILE_TIMEOUT_SECONDS
    ) -> DecompiledFunction:
        """Finds and decompiles a function in a specified binary and returns its pseudo-C code."""

        func = self.find_function(name_or_address)
        return self.decompile_function(func, timeout=timeout)

    def decompile_function(
        self, func: "Function", timeout: int = DEFAULT_DECOMPILE_TIMEOUT_SECONDS
    ) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        if timeout <= 0:
            raise ValueError("Decompiler timeout must be greater than zero")

        monitor = ConsoleTaskMonitor()
        deadline = time.monotonic() + timeout
        with self.decompiler_pool.acquire(timeout=timeout) as decompiler:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for a decompiler after {timeout} seconds")
            ghidra_timeout = max(1, math.ceil(remaining))
            result: DecompileResults = decompiler.decompileFunction(func, ghidra_timeout, monitor)
        if "" == result.getErrorMessage():
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                code = ""
                sig = None
            else:
                code = decompiled.getC()
                sig = decompiled.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None
        return DecompiledFunction(name=self._get_filename(func), code=code, signature=sig)

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """
        Gets all functions within a binary.
        Returns a python list that doesn't need to be re-intialized
        """

        funcs = set()
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.add(func)
        return list(funcs)

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic=False
    ) -> list["Symbol"]:
        """
        Gets all symbols within a binary.
        Returns a python list that doesn't need to be re-initialized.
        """

        symbols = set()
        from ghidra.program.model.symbol import SymbolTable

        st: SymbolTable = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(include_dynamic)

        for sym in all_symbols:
            sym: Symbol
            if not include_externals and sym.isExternal():
                continue
            symbols.add(sym)

        return list(symbols)

    @handle_exceptions
    def get_all_strings(self) -> list[StringInfo]:
        """Gets all defined strings for a binary"""
        try:
            from ghidra.program.util import DefinedStringIterator  # type: ignore

            data_iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            # Support Ghidra 11.3.2
            from ghidra.program.util import DefinedDataIterator

            data_iterator = DefinedDataIterator.definedStrings(self.program)

        strings = []
        for data in data_iterator:
            try:
                string_value = data.getValue()
                strings.append(StringInfo(value=str(string_value), address=str(data.getAddress())))
            except Exception as e:
                logger.debug(f"Could not get string value from data at {data.getAddress()}: {e}")

        return strings

    @staticmethod
    def _matches_query(query: str, symbol_name: str) -> bool:
        """Check if a symbol name matches a query (regex with substring fallback)."""
        try:
            return bool(re.search(query, symbol_name, re.IGNORECASE))
        except re.error:
            return query.lower() in symbol_name.lower()

    @classmethod
    def _symbol_matches_query(cls, query: str, symbol) -> bool:
        """Match against both simple and namespace-qualified symbol names."""
        names = {str(symbol.getName())}
        try:
            names.add(str(symbol.getName(True)))
        except TypeError:
            pass
        return any(cls._matches_query(query, name) for name in names)

    def _symbol_to_info(self, symbol, rm) -> SymbolInfo:
        """Convert a Ghidra Symbol to a SymbolInfo model."""
        ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
        is_thunk = False
        thunk_target = None

        try:
            func = self.program.getFunctionManager().getFunctionAt(symbol.getAddress())
        except Exception:
            func = None

        if func is not None:
            try:
                is_thunk = bool(func.isThunk())
            except Exception:
                is_thunk = False

            if is_thunk:
                try:
                    thunked = func.getThunkedFunction(True)
                except TypeError:
                    thunked = func.getThunkedFunction(False)
                except Exception:
                    thunked = None

                if thunked is not None:
                    thunk_target = (
                        f"{thunked.getSymbol().getName(True)} @ {thunked.getEntryPoint()}"
                    )

        return SymbolInfo(
            name=symbol.getName(),
            address=str(symbol.getAddress()),
            type=str(symbol.getSymbolType()),
            namespace=str(symbol.getParentNamespace()),
            source=str(symbol.getSource()),
            refcount=ref_count,
            external=symbol.isExternal(),
            is_thunk=is_thunk,
            thunk_target=thunk_target,
        )

    @classmethod
    def _symbol_sort_key(cls, query: str, symbol, info: SymbolInfo) -> tuple:
        names = {str(symbol.getName())}
        try:
            names.add(str(symbol.getName(True)))
        except TypeError:
            pass

        query_lc = query.lower()
        exact_name = any(name.lower() == query_lc for name in names)
        return (
            0 if exact_name else 1,
            1 if info.is_thunk else 0,
            1 if info.external else 0,
            -info.refcount,
            info.name.lower(),
            info.address,
        )

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, functions_only: bool = False, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name (supports regex).

        When functions_only=True, searches only function symbols (no labels/variables).
        """

        if not query:
            raise ValueError("Query string is required")

        rm = self.program.getReferenceManager()
        is_regex = bool(_REGEX_META.search(query))

        if functions_only:
            sources = self.get_all_functions(True) if is_regex else self.find_functions(query)
            symbols = (func.getSymbol() for func in sources)
        else:
            symbols = self.get_all_symbols(True) if is_regex else self.find_symbols(query)

        matches = []
        for sym in symbols:
            if not self._symbol_matches_query(query, sym):
                continue
            info = self._symbol_to_info(sym, rm)
            matches.append((sym, info))

        matches.sort(key=lambda item: self._symbol_sort_key(query, item[0], item[1]))
        results = [info for _, info in matches]
        return results[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        exports = []
        symbols = self.program.getSymbolTable().getAllSymbols(True)
        for symbol in symbols:
            if symbol.isExternalEntryPoint():
                if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                    continue
                exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
        return exports[offset : limit + offset]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        imports = []
        symbols = self.program.getSymbolTable().getExternalSymbols()
        for symbol in symbols:
            if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
        return imports[offset : limit + offset]

    @handle_exceptions
    def list_xrefs(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.
        """
        # Use the unified resolver
        sym: Symbol = self.find_symbol(name_or_address)
        addr = sym.getAddress()

        cross_references: list[CrossReferenceInfo] = []
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            from_func = self.program.getFunctionManager().getFunctionContaining(
                ref.getFromAddress()
            )
            cross_references.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references

    @handle_exceptions
    def get_callees(self, name_or_address: str) -> list[str]:
        """Get names of functions called by the given function."""
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(name_or_address)
        monitor = ConsoleTaskMonitor()
        called = func.getCalledFunctions(monitor)
        return [f.getName() for f in called]

    @handle_exceptions
    def get_referenced_strings(self, name_or_address: str) -> list[str]:
        """Get string literals referenced within the given function's body."""
        from ghidra.program.model.data import AbstractStringDataType as StringDataType

        func = self.find_function(name_or_address)
        listing = self.program.getListing()
        strings: list[str] = []
        body = func.getBody()

        for insn in listing.getInstructions(body, True):
            for ref in insn.getReferencesFrom():
                data = listing.getDefinedDataAt(ref.getToAddress())
                if data is not None and isinstance(data.getDataType(), StringDataType):
                    val = data.getValue()
                    if val is not None:
                        strings.append(str(val))

        return strings

    def _search_code_literal(
        self,
        literal_results: typing.Any,
        limit: int,
        offset: int,
        include_full_code: bool,
        preview_length: int,
    ) -> list[CodeSearchResult]:
        search_results: list[CodeSearchResult] = []
        if literal_results and literal_results.get("documents"):
            # Apply offset and limit
            docs = literal_results["documents"] or []
            metadatas = literal_results["metadatas"] or []

            # Paginate
            start_idx = offset
            end_idx = offset + limit
            paginated_docs = docs[start_idx:end_idx]
            paginated_meta = metadatas[start_idx:end_idx] if metadatas else []

            for i, doc in enumerate(paginated_docs):
                metadata = paginated_meta[i] if i < len(paginated_meta) else {}
                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=1.0,  # Exact match
                        search_mode=SearchMode.LITERAL,
                        preview=preview,
                    )
                )
        return search_results

    def _search_code_semantic(
        self,
        query: str,
        limit: int,
        offset: int,
        similarity_threshold: float,
        include_full_code: bool,
        preview_length: int,
        total_functions: int,  # Added total_functions to correctly calculate semantic_total
    ) -> tuple[list[CodeSearchResult], int]:  # Changed return type to int for semantic_total
        assert self.program_info.code_collection is not None
        search_results: list[CodeSearchResult] = []
        # Semantic search
        results = self.program_info.code_collection.query(
            query_texts=[query],
            n_results=limit + offset,
        )

        docs_list = results.get("documents") if results else None
        semantic_total = total_functions  # Initialize semantic_total here

        if results and docs_list and len(docs_list) > 0 and docs_list[0]:
            # Apply offset
            docs = docs_list[0][offset:]
            metadatas_list = results.get("metadatas")
            distances_list = results.get("distances")
            metadatas = (
                metadatas_list[0][offset:] if metadatas_list and len(metadatas_list) > 0 else []
            )
            distances = (
                distances_list[0][offset:] if distances_list and len(distances_list) > 0 else []
            )

            for i, doc in enumerate(docs):
                metadata = metadatas[i] if i < len(metadatas) else {}
                distance = distances[i] if i < len(distances) else 0
                # ChromaDB uses L2 distance by default (0 = identical, can be > 1)
                # Normalize to 0-1 range where 1 = identical
                similarity = 1 / (1 + distance)

                # Skip results below similarity threshold
                if similarity < similarity_threshold:
                    continue

                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=similarity,
                        search_mode=SearchMode.SEMANTIC,
                        preview=preview,
                    )
                )

            # Refine semantic_total
            # If we got fewer results than requested limit (after filtering),
            # providing we fetched enough (n_results was limit+offset)
            # and we processed strictly what we asked for.
            # Actually, if the RAW result count was less than n_results, we know we exhausted
            # the DB.
            # If valid_results_count < limit, we *might* have exhausted matches above threshold
            # in this batch.
            # A better heuristic: if result count < limit, we found everything.
            if len(search_results) < limit:
                # This is only accurate if we assume we found "the end".
                # However, since we queried limit + offset, if we got less than limit (and we
                # started at offset),
                # it implies we are at the tail.
                semantic_total = offset + len(search_results)

        return search_results, semantic_total

    @handle_exceptions
    def search_code(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        search_mode: SearchMode = SearchMode.SEMANTIC,
        include_full_code: bool = True,
        preview_length: int = 500,
        similarity_threshold: float = 0.0,
    ) -> CodeSearchResults:
        """
        Searches the code in the binary for a given query.

        Supports semantic (vector similarity) and literal (exact match) modes.
        Always returns dual-mode counts to help LLM decide on mode switching.

        Args:
            similarity_threshold: Minimum similarity score (0.0-1.0) for semantic results.
                                  Results below this threshold are filtered out.
        """
        if not self.program_info.code_collection:
            raise ValueError(
                "Code indexing is not complete for this binary. Please try again later."
            )

        # ALWAYS get literal count (reuse for literal mode search)
        literal_results = self.program_info.code_collection.get(where_document={"$contains": query})
        literal_total = (
            len(literal_results["ids"]) if literal_results and literal_results.get("ids") else 0
        )

        # Total functions in collection (absolute total)
        total_functions = self.program_info.code_collection.count()

        # Default semantic total to "available" (filtered by limit)
        # If we filter and get FEWER than requested, we effectively found "all" above threshold
        # in this range.
        # But we don't know beyond the limit.
        # So we default to total_functions as "estimated matches" if we hit the limit.
        semantic_total = total_functions

        search_results: list[CodeSearchResult] = []

        if search_mode == SearchMode.LITERAL:
            search_results = self._search_code_literal(
                literal_results, limit, offset, include_full_code, preview_length
            )
        else:
            search_results, estimated_total = self._search_code_semantic(
                query,
                limit,
                offset,
                similarity_threshold,
                include_full_code,
                preview_length,
                total_functions,
            )
            if estimated_total is not None:
                semantic_total = estimated_total

        return CodeSearchResults(
            results=search_results,
            query=query,
            search_mode=search_mode,
            returned_count=len(search_results),
            offset=offset,
            limit=limit,
            literal_total=literal_total,
            semantic_total=semantic_total,
            total_functions=total_functions,
        )

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary using substring matching."""

        if self.program_info.strings is None:
            raise ValueError(
                "String indexing is not complete for this binary. Please try again later."
            )

        query_lower = query.lower()
        return [
            StringSearchResult(value=s.value, address=s.address, similarity=1.0)
            for s in self.program_info.strings
            if query_lower in s.value.lower()
        ][:limit]

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        # Maximum size limit to prevent excessive memory reads
        max_read_size = 8192

        if size <= 0:
            raise ValueError("size must be > 0")

        if size > max_read_size:
            raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

        # Get address factory and parse address
        af = self.program.getAddressFactory()

        try:
            # Handle common hex address formats
            addr_str = address
            if address.lower().startswith("0x"):
                addr_str = address[2:]

            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        # Check if address is in valid memory
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        # Use JPype to handle byte arrays properly for PyGhidra
        # Create Java byte array - JPype's runtime magic confuses static type checkers
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)

        # Convert Java signed bytes (-128 to 127) to Python unsigned (0 to 255)
        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])  # type: ignore[reportGeneralTypeIssues]
        else:
            data = b""

        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
        )

    @handle_exceptions
    def disassemble(
        self, address: str, count: int = 20, include_bytes: bool = False
    ) -> "DisassembleResult":
        """Disassembles instructions starting at an address.

        Returns a compact, whitespace-aligned text listing rather than per-instruction
        JSON objects to minimize token usage. Raw instruction bytes are omitted unless
        ``include_bytes`` is True.
        """
        af = self.program.getAddressFactory()
        try:
            addr_str = address[2:] if address.lower().startswith("0x") else address
            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        if not self.program.getMemory().contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        listing = self.program.getListing()
        rows: list[tuple[str, str, str, str]] = []
        for insn in listing.getInstructions(addr, True):
            if len(rows) >= count:
                break
            raw = bytes([b & 0xFF for b in insn.getBytes()])
            operand_parts = []
            for i in range(insn.getNumOperands()):
                rep = insn.getDefaultOperandRepresentation(i)
                if rep:
                    operand_parts.append(str(rep))
            rows.append(
                (
                    str(insn.getAddress()),
                    raw.hex(),
                    str(insn.getMnemonicString()),
                    ",".join(operand_parts),
                )
            )

        listing_text = self._format_disassembly(rows, include_bytes=include_bytes)
        return DisassembleResult(address=str(addr), count=len(rows), listing=listing_text)

    @staticmethod
    def _format_disassembly(rows: list[tuple[str, str, str, str]], include_bytes: bool) -> str:
        """Render disassembly rows as a compact, single-space-separated text listing.

        Columns are ordered address [bytes] mnemonic operands. No alignment padding is
        used: the consumer is an LLM that parses each line positionally, and padding
        spaces only add tokens without aiding comprehension.
        """
        lines = []
        for addr, raw, mnem, operands in rows:
            parts = [addr]
            if include_bytes:
                parts.append(raw)
            parts.append(mnem)
            if operands:
                parts.append(operands)
            lines.append(" ".join(parts))
        return "\n".join(lines)

    @handle_exceptions
    def gen_callgraph(
        self,
        function_name_or_address: str,
        cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
        cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
    ) -> CallGraphResult:
        """Generates a call graph for a specified function."""

        cg_func = self.find_function(function_name_or_address)
        mermaid_url: str = ""

        # Call the ghidrecomp function
        name, direction, _, graphs_data = gen_callgraph(
            func=cg_func,
            max_display_depth=max_depth,
            direction=cg_direction.value,
            max_run_time=max_run_time,
            name=cg_func.getSymbol().getName(True),
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
            wrap_mermaid=False,
        )

        selected_graph_content = ""
        for graph_type, graph_content in graphs_data:
            if CallGraphDisplayType(graph_type) == cg_display_type:
                selected_graph_content = graph_content
                break

        if not selected_graph_content:
            raise ValueError(
                f"Cg display type {cg_display_type.value} not found for function {cg_func}."
            )

        for graph_type, graph_content in graphs_data:
            if graph_type == "mermaid_url":
                mermaid_url = graph_content.split("\n")[0]
                break

        return CallGraphResult(
            function_name=name,
            direction=CallGraphDirection(direction),
            display_type=cg_display_type,
            graph=selected_graph_content,
            mermaid_url=mermaid_url,
        )

    @handle_exceptions
    def rename_function(self, name_or_address: str, new_name: str) -> dict:
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(name_or_address)
        old_name = str(func.getName())
        address = str(func.getEntryPoint())

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: rename {old_name} -> {new_name}",
        ):
            func.setName(new_name, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
        }

    @handle_exceptions
    def rename_symbol(self, name_or_address: str, new_name: str) -> dict:
        """Rename a symbol by name or address. Unnamed DAT_* labels resolve by address only."""
        from ghidra.program.model.symbol import SourceType

        symbol = self.find_symbol(name_or_address)
        old_name = str(symbol.getName())
        address = str(symbol.getAddress())

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: rename symbol {old_name} -> {new_name}",
        ):
            symbol.setName(new_name, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()

        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
        }

    @handle_exceptions
    def rename_variable(
        self,
        function_name_or_address: str,
        variable_name: str,
        new_name: str,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func, variable_kind, variable = self._resolve_function_variable(
            function_name_or_address, variable_name
        )
        old_name = str(variable_name)
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: rename {variable_kind} {old_name} -> {new_name}",
        ):
            variable.setName(new_name, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "variable_kind": variable_kind,
            "old_name": old_name,
            "new_name": new_name,
        }

    @handle_exceptions
    def set_variable_type(
        self,
        function_name_or_address: str,
        variable_name: str,
        type_name: str,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func, variable_kind, variable = self._resolve_function_variable(
            function_name_or_address, variable_name
        )
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_type = str(variable.getDataType().getDisplayName())
        data_type = self._parse_data_type(type_name)

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set {variable_kind} type {variable_name} -> {type_name}",
        ):
            variable.setDataType(data_type, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "variable_kind": variable_kind,
            "variable_name": str(variable.getName()),
            "old_type": old_type,
            "new_type": str(variable.getDataType().getDisplayName()),
        }

    @handle_exceptions
    def set_function_prototype(
        self,
        function_name_or_address: str,
        prototype: str,
    ) -> dict:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_prototype = str(func.getSignature())

        parser = FunctionSignatureParser(
            self.program.getDataTypeManager(), typing.cast(typing.Any, None)
        )
        parsed_signature = parser.parse(func.getSignature(False), prototype)
        cmd = ApplyFunctionSignatureCmd(
            func.getEntryPoint(),
            parsed_signature,
            SourceType.USER_DEFINED,
        )

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set function prototype {function_name}",
        ):
            if not cmd.applyTo(self.program, TaskMonitor.DUMMY):
                message = cmd.getStatusMsg() or f"Failed to apply function prototype: {prototype}"
                raise ValueError(message)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "old_prototype": old_prototype,
            "new_prototype": str(func.getSignature()),
        }

    @handle_exceptions
    def set_comment(self, target: str, comment: str, comment_type: str) -> dict:
        try:
            from ghidra.program.model.listing import CommentType

            listing_comment_types = {
                "plate": CommentType.PLATE,
                "pre": CommentType.PRE,
                "eol": CommentType.EOL,
                "post": CommentType.POST,
                "repeatable": CommentType.REPEATABLE,
            }
        except ImportError:
            from ghidra.program.model.listing import CodeUnit

            listing_comment_types = {
                "plate": CodeUnit.PLATE_COMMENT,
                "pre": CodeUnit.PRE_COMMENT,
                "eol": CodeUnit.EOL_COMMENT,
                "post": CodeUnit.POST_COMMENT,
                "repeatable": CodeUnit.REPEATABLE_COMMENT,
            }

        normalized_type = comment_type.lower()
        if normalized_type == "decompiler":
            func = self.find_function(target)
            addr = func.getEntryPoint()

            with ghidra_transaction(
                self.program,
                f"pyghidra-mcp: set function comment @ {addr}",
            ):
                func.setComment(comment)

            self.invalidate_decompiler_cache()
            return {
                "address": str(addr),
                "comment": comment,
                "comment_type": "decompiler",
            }

        ghidra_comment_type = listing_comment_types.get(normalized_type)
        if ghidra_comment_type is None:
            allowed = ["decompiler", *listing_comment_types.keys()]
            raise ValueError(f"Invalid comment_type '{comment_type}'. Expected one of: {allowed}")

        addr = self._resolve_comment_target_address(target)
        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set {normalized_type} comment @ {addr}",
        ):
            self.program.getListing().setComment(addr, ghidra_comment_type, comment)

        self.invalidate_decompiler_cache()
        return {
            "address": str(addr),
            "comment": comment,
            "comment_type": normalized_type,
        }

    def invalidate_decompiler_cache(self) -> None:
        try:
            self.decompiler_pool.invalidate_all()
        except Exception:
            logger.debug("Failed to invalidate decompiler cache", exc_info=True)

    def _parse_address(self, address: str):
        addr_str = address[2:] if address.lower().startswith("0x") else address
        addr = self.program.getAddressFactory().getAddress(addr_str)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        return addr

    def _resolve_comment_target_address(self, target: str):
        try:
            return self._parse_address(target)
        except Exception:
            pass

        if target.isdigit():
            addr = self.program.getAddressFactory().getDefaultAddressSpace().getAddress(int(target))
            if addr is not None:
                return addr

        try:
            return self.find_symbol(target).getAddress()
        except Exception:
            pass

        try:
            return self.find_function(target).getEntryPoint()
        except Exception:
            pass

        raise ValueError(
            f"Could not resolve comment target '{target}' as an address, symbol, or function."
        )
