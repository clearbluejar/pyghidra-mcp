"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import logging
import re
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
    ExportInfo,
    ImportInfo,
    SearchMode,
    StringInfo,
    StringSearchResult,
    SymbolInfo,
)

_REGEX_META = re.compile(r"[\\^$.|?*+(){}\[\]]")

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo

logger = logging.getLogger(__name__)


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
        variable_kind: typing.Literal["parameter", "local"] | None = None,
    ) -> tuple["Function", str, typing.Any]:
        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())

        matches: list[tuple[str, typing.Any]] = []
        if variable_kind in {None, "parameter"}:
            for param in func.getParameters():
                if str(param.getName()) == variable_name:
                    matches.append(("parameter", param))
        if variable_kind in {None, "local"}:
            for local in func.getLocalVariables():
                if str(local.getName()) == variable_name:
                    matches.append(("local", local))

        if not matches:
            qualifier = f" {variable_kind}" if variable_kind else ""
            raise ValueError(
                f"Variable{qualifier} '{variable_name}' not found in function '{function_name}'."
            )
        if len(matches) > 1:
            kinds = ", ".join(kind for kind, _ in matches)
            raise ValueError(
                f"Ambiguous variable '{variable_name}' in function '{function_name}' ({kinds})."
            )

        resolved_variable_kind, variable = matches[0]
        return func, resolved_variable_kind, variable

    def _parse_data_type(self, type_name: str):
        from ghidra.util.data import DataTypeParser  # type: ignore
        from ghidra.util.data.DataTypeParser import AllowedDataTypes  # type: ignore

        dtm = self.program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, typing.cast(typing.Any, None), AllowedDataTypes.DYNAMIC)
        return parser.parse(type_name)

    def _iter_values(self, values):
        if hasattr(values, "hasNext") and hasattr(values, "next"):
            while values.hasNext():
                yield values.next()
            return
        yield from values

    def _data_type_path(self, data_type) -> str:
        return str(data_type.getPathName())

    def _data_type_category_path(self, data_type) -> str:
        return str(data_type.getCategoryPath().getPath())

    def _data_type_kind(self, data_type) -> str:
        class_name = data_type.__class__.__name__.lower()
        if "typedef" in class_name or (
            hasattr(data_type, "getBaseDataType") and not hasattr(data_type, "getDefinedComponents")
        ):
            return "typedef"
        if "structure" in class_name or class_name.startswith("struct"):
            return "structure"
        if "union" in class_name:
            return "union"
        if hasattr(data_type, "getDefinedComponents"):
            return "composite"
        if "enum" in class_name:
            return "enum"
        if "pointer" in class_name:
            return "pointer"
        if "array" in class_name:
            return "array"
        if "functiondefinition" in class_name or "functiondef" in class_name:
            return "function_definition"
        return class_name

    def _data_type_size(self, data_type) -> int:
        return int(data_type.getLength())

    def _data_type_aligned_size(self, data_type) -> int:
        aligned_length = getattr(data_type, "getAlignedLength", None)
        if callable(aligned_length):
            return int(aligned_length())
        return self._data_type_size(data_type)

    def _unwrap_typedef(self, data_type):
        if self._data_type_kind(data_type) != "typedef":
            return None
        base_type = getattr(data_type, "getBaseDataType", None)
        if callable(base_type):
            return base_type()
        data_type_getter = getattr(data_type, "getDataType", None)
        if callable(data_type_getter):
            return data_type_getter()
        return None

    def _serialize_data_type_field(self, component) -> dict:
        field_type = component.getDataType()
        field_name = component.getFieldName()
        default_field_name = getattr(component, "getDefaultFieldName", None)
        if field_name is None and callable(default_field_name):
            field_name = default_field_name()
        comment = component.getComment()
        return {
            "ordinal": int(component.getOrdinal()),
            "offset": int(component.getOffset()),
            "length": int(component.getLength()),
            "field_name": "" if field_name is None else str(field_name),
            "type_name": str(field_type.getDisplayName()),
            "type_path": self._data_type_path(field_type),
            "comment": None if comment is None else str(comment),
        }

    def _serialize_data_type_reference(self, data_type) -> dict:
        return {
            "name": str(data_type.getName()),
            "display_name": str(data_type.getDisplayName()),
            "path": self._data_type_path(data_type),
            "category_path": self._data_type_category_path(data_type),
            "kind": self._data_type_kind(data_type),
            "size": self._data_type_size(data_type),
        }

    def _resolve_data_type(self, data_type_name_or_path: str):
        dtm = self.program.getDataTypeManager()
        all_data_types = list(self._iter_values(dtm.getAllDataTypes()))

        if data_type_name_or_path.startswith("/"):
            for data_type in all_data_types:
                if self._data_type_path(data_type) == data_type_name_or_path:
                    return data_type
            raise ValueError(f"Data type '{data_type_name_or_path}' not found.")

        matches = [
            data_type
            for data_type in all_data_types
            if str(data_type.getName()) == data_type_name_or_path
        ]
        if not matches:
            raise ValueError(f"Data type '{data_type_name_or_path}' not found.")
        if len(matches) > 1:
            candidates = ", ".join(sorted(self._data_type_path(data_type) for data_type in matches))
            raise ValueError(
                f"Ambiguous data type '{data_type_name_or_path}'. Matching paths: {candidates}"
            )
        return matches[0]

    def _resolve_or_parse_data_type(self, type_name_or_path: str):
        if type_name_or_path.startswith("/"):
            return self._resolve_data_type(type_name_or_path)
        try:
            return self._resolve_data_type(type_name_or_path)
        except ValueError as exact_error:
            if "Ambiguous data type" in str(exact_error):
                raise
            return self._parse_data_type(type_name_or_path)

    def _lookup_functions(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
        include_externals: bool = True,
    ) -> list["Function"]:
        """
        Resolve functions by name or address.
        Returns a flat list of unique Function objects.
        Search modes (exact, partial) are optional and only applied if enabled.
        """
        af = self.program.getAddressFactory()
        fm = self.program.getFunctionManager()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return [func]
        except Exception:
            pass  # Not an address, fall back to name search

        name_lc = name_or_address.lower()
        functions = self.get_all_functions(include_externals=include_externals)
        seen: set = set()
        matches: list[Function] = []

        if exact:
            for f in functions:
                key = f.getEntryPoint()
                if key not in seen and name_lc == f.getSymbol().getName(True).lower():
                    seen.add(key)
                    matches.append(f)

        if partial:
            for f in functions:
                key = f.getEntryPoint()
                if key not in seen and name_lc in f.getSymbol().getName(True).lower():
                    seen.add(key)
                    matches.append(f)

        return matches

    @handle_exceptions
    def find_function(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> "Function":
        """
        Resolve a single function by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_functions(
            name_or_address, exact=True, partial=False, include_externals=include_externals
        )

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
    def find_functions(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> list["Function"]:
        """
        Return all functions that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_functions(
            name_or_address, exact=True, partial=True, include_externals=include_externals
        )

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
        dynamic: bool = False,
    ) -> list["Symbol"]:
        """
        Resolve symbols by name or address.
        Returns a single flat list of unique Symbol objects.
        Search modes (exact, partial, dynamic) are optional and only applied if enabled.
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
        except Exception:
            pass  # Not an address, fall back to name search

        name_lc = name_or_address.lower()
        matches: set[Symbol] = set()

        # Base symbol set (externals only once)
        base_symbols = self.get_all_symbols(include_externals=True)

        # Exact match
        if exact:
            matches.update(s for s in base_symbols if name_lc == s.getName(True).lower())

        # Partial match
        if partial:
            matches.update(s for s in base_symbols if name_lc in s.getName(True).lower())

        # Dynamic match (requires second scan)
        if dynamic:
            dyn_symbols = self.get_all_symbols(include_externals=True, include_dynamic=True)
            matches.update(s for s in dyn_symbols if name_lc in s.getName(True).lower())

        return list(matches)

    @handle_exceptions
    def find_symbols(self, name_or_address: str) -> list["Symbol"]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, exact=True, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """
        Resolve a single symbol by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, exact=True, partial=False)

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
        self, name_or_address: str, timeout: int = 0
    ) -> DecompiledFunction:
        """Finds and decompiles a function in a specified binary and returns its pseudo-C code."""

        func = self.find_function(name_or_address)
        return self.decompile_function(func, timeout=timeout)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        with self.decompiler_pool.acquire() as decompiler:
            result: DecompileResults = decompiler.decompileFunction(func, timeout, monitor)
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
        variable_kind: typing.Literal["parameter", "local"] | None = None,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func, resolved_variable_kind, variable = self._resolve_function_variable(
            function_name_or_address, variable_name, variable_kind
        )
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_data_type = variable.getDataType()
        old_type = str(old_data_type.getDisplayName())
        data_type = self._resolve_or_parse_data_type(type_name)

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set {resolved_variable_kind} type {variable_name} -> {type_name}",
        ):
            variable.setDataType(data_type, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        new_data_type = variable.getDataType()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "variable_kind": resolved_variable_kind,
            "variable_name": str(variable.getName()),
            "old_type": old_type,
            "old_type_path": self._data_type_path(old_data_type),
            "new_type": str(new_data_type.getDisplayName()),
            "new_type_path": self._data_type_path(new_data_type),
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
    def set_function_return_type(
        self,
        function_name_or_address: str,
        type_name_or_path: str,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_return_type = func.getReturnType()
        new_return_type = self._resolve_or_parse_data_type(type_name_or_path)

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set function return type {function_name} -> {type_name_or_path}",
        ):
            func.setReturnType(new_return_type, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        applied_return_type = func.getReturnType()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "old_return_type": str(old_return_type.getDisplayName()),
            "old_return_type_path": self._data_type_path(old_return_type),
            "new_return_type": str(applied_return_type.getDisplayName()),
            "new_return_type_path": self._data_type_path(applied_return_type),
        }

    def _address_add(self, address, offset: int):
        add_no_wrap = getattr(address, "addNoWrap", None)
        if callable(add_no_wrap):
            return add_no_wrap(offset)
        return address.add(offset)

    def _validate_data_range(self, mem, start_addr, end_addr, requested_address: str) -> None:
        if not mem.contains(start_addr):
            raise ValueError(f"Address {requested_address} is not in mapped memory")
        if not mem.contains(end_addr):
            raise ValueError(f"Data type range {start_addr}..{end_addr} is not fully mapped")

        get_block = getattr(mem, "getBlock", None)
        if not callable(get_block):
            return
        start_block = get_block(start_addr)
        end_block = get_block(end_addr)
        if start_block is None or end_block is None:
            raise ValueError(f"Data type range {start_addr}..{end_addr} is not fully mapped")
        if start_block != end_block:
            raise ValueError(f"Data type range {start_addr}..{end_addr} crosses memory blocks")

    @handle_exceptions
    def set_data_type_at_address(
        self,
        address: str,
        type_name_or_path: str,
        clear_existing: bool = True,
    ) -> dict:
        addr = self._parse_address(address)
        mem = self.program.getMemory()
        listing = self.program.getListing()
        old_data = listing.getDefinedDataAt(addr)
        old_data_type = old_data.getDataType() if old_data is not None else None
        data_type = self._resolve_or_parse_data_type(type_name_or_path)
        length = self._data_type_size(data_type)
        if length <= 0:
            length = int(self.program.getDefaultPointerSize())
        if length <= 0:
            raise ValueError(f"Data type '{type_name_or_path}' has non-positive length {length}")
        try:
            end_addr = self._address_add(addr, length - 1)
        except Exception as exc:
            raise ValueError(
                f"Data type '{type_name_or_path}' of length {length} does not fit at address {addr}"
            ) from exc
        self._validate_data_range(mem, addr, end_addr, address)

        with ghidra_transaction(
            self.program,
            f"pyghidra-mcp: set data type at {addr} -> {type_name_or_path}",
        ):
            if clear_existing:
                listing.clearCodeUnits(addr, end_addr, False)
            data = listing.createData(addr, data_type)

        self.invalidate_decompiler_cache()
        new_data_type = data.getDataType()
        return {
            "address": str(addr),
            "old_type": None if old_data_type is None else str(old_data_type.getDisplayName()),
            "old_type_path": None if old_data_type is None else self._data_type_path(old_data_type),
            "new_type": str(new_data_type.getDisplayName()),
            "new_type_path": self._data_type_path(new_data_type),
            "length": int(data.getLength()),
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

    def _is_builtin_data_type(self, data_type) -> bool:
        category_path = self._data_type_category_path(data_type).lower()
        return category_path in {"/builtin", "/builtins", "/built-in"} or category_path.startswith(
            ("/builtin/", "/builtins/", "/built-in/")
        )

    def _data_type_in_category_subtree(self, data_type, root: str) -> bool:
        path = self._data_type_category_path(data_type)
        return path == root or path.startswith(f"{root}/")

    def _include_data_type_by_default(self, data_type, include_builtins: bool) -> bool:
        from pyghidra_mcp.header_import import CANONICAL_CATEGORY_ROOT

        if self._data_type_in_category_subtree(data_type, CANONICAL_CATEGORY_ROOT):
            return True
        if include_builtins:
            return True
        category_path = self._data_type_category_path(data_type)
        return category_path not in {"", "/"} and not self._is_builtin_data_type(data_type)

    def _data_type_matches_query(self, data_type, query: str) -> bool:
        searchable = (
            str(data_type.getName()),
            str(data_type.getDisplayName()),
            self._data_type_path(data_type),
        )
        return any(self._matches_query(query, value) for value in searchable)

    @handle_exceptions
    def list_data_types(
        self,
        query: str = ".*",
        category_path: str | None = None,
        include_builtins: bool = False,
        offset: int = 0,
        limit: int = 50,
    ) -> dict:
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit < 0:
            raise ValueError("limit must be >= 0")

        matches = []
        for data_type in self._iter_values(self.program.getDataTypeManager().getAllDataTypes()):
            if category_path is not None and not self._data_type_in_category_subtree(
                data_type, category_path
            ):
                continue
            if category_path is None and not self._include_data_type_by_default(
                data_type, include_builtins
            ):
                continue
            if not self._data_type_matches_query(data_type, query):
                continue
            matches.append(data_type)

        matches.sort(key=lambda data_type: self._data_type_path(data_type).lower())
        paged_matches = matches[offset : offset + limit]
        return {
            "data_types": [
                self._serialize_data_type_reference(data_type) for data_type in paged_matches
            ],
            "total_matches": len(matches),
        }

    @handle_exceptions
    def describe_data_type(self, data_type_name_or_path: str) -> dict:
        if not data_type_name_or_path:
            raise ValueError("data_type_name_or_path is required.")

        data_type = self._resolve_data_type(data_type_name_or_path)
        kind = self._data_type_kind(data_type)
        base_type = self._unwrap_typedef(data_type)
        effective_type = base_type or data_type
        fields: list[dict] = []

        if hasattr(effective_type, "getDefinedComponents"):
            fields = [
                self._serialize_data_type_field(component)
                for component in effective_type.getDefinedComponents()
            ]

        response = {
            "requested_name_or_path": data_type_name_or_path,
            "name": str(data_type.getName()),
            "display_name": str(data_type.getDisplayName()),
            "path": self._data_type_path(data_type),
            "category_path": self._data_type_category_path(data_type),
            "kind": kind,
            "size": self._data_type_size(data_type),
            "aligned_size": self._data_type_aligned_size(data_type),
            "description": str(data_type.getDescription()) if data_type.getDescription() else None,
            "base_type_name": None,
            "base_type_path": None,
            "base_type_kind": None,
            "fields": fields,
        }

        if base_type is not None:
            response.update(
                {
                    "base_type_name": str(base_type.getDisplayName()),
                    "base_type_path": self._data_type_path(base_type),
                    "base_type_kind": self._data_type_kind(base_type),
                }
            )

        return response

    @handle_exceptions
    def import_header_types(
        self,
        header_path: str | None = None,
        validate_only: bool = False,
        *,
        header_content: str | None = None,
        header_name: str | None = None,
        include_files: dict[str, str] | None = None,
        header_files: list[dict[str, str]] | None = None,
    ) -> dict:
        from pyghidra_mcp.header_import import CANONICAL_CATEGORY_ROOT, apply_header_import_plan
        from pyghidra_mcp.header_import.planning import (
            build_header_import_plan,
            build_header_import_plan_from_files,
            build_header_import_plan_from_source,
            translate_header_path,
        )

        mode_count = sum(
            mode_enabled
            for mode_enabled in (
                header_path is not None,
                header_content is not None,
                header_files is not None,
            )
        )
        if mode_count != 1:
            raise ValueError("Use exactly one of header_path, header_content, or header_files")

        if header_files is not None:
            if header_name is not None or include_files is not None:
                raise ValueError(
                    "header_files cannot be combined with header_name or include_files"
                )
            plan = build_header_import_plan_from_files(header_files)
        elif header_content is not None:
            plan = build_header_import_plan_from_source(
                header_content,
                header_name=header_name or "input.h",
                include_files=include_files,
            )
        else:
            if not header_path:
                raise ValueError("header_path is required")
            plan = build_header_import_plan(translate_header_path(header_path))
        diagnostics = [
            {
                "severity": diagnostic.severity,
                "message": diagnostic.message,
                "location": diagnostic.location,
            }
            for diagnostic in plan.diagnostics
        ]

        if validate_only:
            return {
                "header_path": str(plan.header_path),
                "category_root": CANONICAL_CATEGORY_ROOT,
                "validate_only": True,
                "resolved_local_includes": [str(path) for path in plan.resolved_local_includes],
                "resolved_system_includes": list(plan.resolved_system_includes),
                "created_types": [],
                "updated_types": [],
                "created_type_refs": [],
                "updated_type_refs": [],
                "diagnostics": diagnostics,
            }

        with ghidra_transaction(self.program, "Import header types"):
            apply_result = apply_header_import_plan(self.program, plan)
        self.invalidate_decompiler_cache()

        def serialize_paths(paths: tuple[str, ...]) -> list[dict]:
            return [
                self._serialize_data_type_reference(self._resolve_data_type(path)) for path in paths
            ]

        return {
            "header_path": str(plan.header_path),
            "category_root": apply_result.category_root,
            "validate_only": False,
            "resolved_local_includes": [str(path) for path in plan.resolved_local_includes],
            "resolved_system_includes": list(plan.resolved_system_includes),
            "created_types": list(apply_result.created_types),
            "updated_types": list(apply_result.updated_types),
            "created_type_refs": serialize_paths(apply_result.created_type_paths),
            "updated_type_refs": serialize_paths(apply_result.updated_type_paths),
            "diagnostics": diagnostics,
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
