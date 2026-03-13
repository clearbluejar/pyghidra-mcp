"""
Comprehensive tool implementations for pyghidra-mcp.
"""

from __future__ import annotations

import functools
import logging
import re
import typing

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

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo

logger = logging.getLogger(__name__)


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

    def __init__(self, program_info: ProgramInfo):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler = program_info.decompiler
        self._cache_version = getattr(program_info, "derived_cache_version", 0)
        self._functions_cache: dict[bool, list[Function]] = {}
        self._symbols_cache: dict[tuple[bool, bool], list[Symbol]] = {}
        self._strings_cache: list[StringInfo] | None = None
        self._export_symbols_cache: list[Symbol] | None = None
        self._import_symbols_cache: list[Symbol] | None = None
        self._code_collection_count: int | None = None

    def _ensure_cache_version(self) -> None:
        current_version = getattr(self.program_info, "derived_cache_version", 0)
        if current_version != self._cache_version:
            self.invalidate_derived_caches(current_version)

    def invalidate_derived_caches(self, version: int | None = None) -> None:
        """Invalidate cached lookup data derived from the program."""
        self._functions_cache.clear()
        self._symbols_cache.clear()
        self._strings_cache = None
        self._export_symbols_cache = None
        self._import_symbols_cache = None
        self._code_collection_count = None
        if version is None:
            version = getattr(self.program_info, "derived_cache_version", 0)
        self._cache_version = version

    def _get_code_collection_count(self) -> int:
        self._ensure_cache_version()
        if self._code_collection_count is None:
            assert self.program_info.code_collection is not None
            self._code_collection_count = self.program_info.code_collection.count()
        return self._code_collection_count

    def _get_export_symbols(self) -> list[Symbol]:
        self._ensure_cache_version()
        if self._export_symbols_cache is None:
            symbols = self.program.getSymbolTable().getAllSymbols(True)
            self._export_symbols_cache = [
                symbol for symbol in symbols if symbol.isExternalEntryPoint()
            ]
        return self._export_symbols_cache

    def _get_import_symbols(self) -> list[Symbol]:
        self._ensure_cache_version()
        if self._import_symbols_cache is None:
            self._import_symbols_cache = list(self.program.getSymbolTable().getExternalSymbols())
        return self._import_symbols_cache

    def _get_filename(self, func: Function):
        max_path_len = 50
        return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"

    def _lookup_functions(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
        include_externals: bool = True,
    ) -> list[Function]:
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
    ) -> Function:
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
    ) -> list[Function]:
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
    ) -> list[Symbol]:
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
    def find_symbols(self, name_or_address: str) -> list[Symbol]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, exact=True, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> Symbol:
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
        return self.decompile_function(func)

    def decompile_function(self, func: Function, timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        result: DecompileResults = self.decompiler.decompileFunction(func, timeout, monitor)
        if "" == result.getErrorMessage():
            code = result.decompiledFunction.getC()
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None
        return DecompiledFunction(name=self._get_filename(func), code=code, signature=sig)

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list[Function]:
        """
        Gets all functions within a binary.
        Returns a python list that doesn't need to be re-intialized
        """
        self._ensure_cache_version()
        cached = self._functions_cache.get(include_externals)
        if cached is not None:
            return cached

        funcs = []
        seen = set()
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            key = func.getEntryPoint()
            if key in seen:
                continue
            seen.add(key)
            funcs.append(func)

        self._functions_cache[include_externals] = funcs
        return funcs

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic=False
    ) -> list[Symbol]:
        """
        Gets all symbols within a binary.
        Returns a python list that doesn't need to be re-initialized.
        """
        self._ensure_cache_version()
        cache_key = (include_externals, include_dynamic)
        cached = self._symbols_cache.get(cache_key)
        if cached is not None:
            return cached

        symbols = []
        seen = set()
        st = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(include_dynamic)

        for sym in all_symbols:
            sym: Symbol
            if not include_externals and sym.isExternal():
                continue
            if sym in seen:
                continue
            seen.add(sym)
            symbols.append(sym)

        self._symbols_cache[cache_key] = symbols
        return symbols

    @handle_exceptions
    def get_all_strings(self) -> list[StringInfo]:
        """Gets all defined strings for a binary"""
        self._ensure_cache_version()
        if self._strings_cache is not None:
            return self._strings_cache

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

        self._strings_cache = strings
        return strings

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""

        if not query:
            raise ValueError("Query string is required")

        query_lc = query.lower()
        symbols = [
            symbol
            for symbol in self.get_all_symbols(include_externals=True)
            if query_lc in symbol.getName(True).lower()
        ]
        paginated_symbols = symbols[offset : offset + limit]
        rm = self.program.getReferenceManager()

        return [
            SymbolInfo(
                name=symbol.name,
                address=str(symbol.getAddress()),
                type=str(symbol.getSymbolType()),
                namespace=str(symbol.getParentNamespace()),
                source=str(symbol.getSource()),
                refcount=len(list(rm.getReferencesTo(symbol.getAddress()))),
                external=symbol.isExternal(),
            )
            for symbol in paginated_symbols
        ]

    @handle_exceptions
    def search_functions_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for functions within a binary by name."""

        if not query:
            raise ValueError("Query string is required")

        query_lc = query.lower()
        functions = [
            func
            for func in self.get_all_functions()
            if query_lc in func.getSymbol().getName(True).lower()
        ]
        paginated_functions = functions[offset : offset + limit]
        rm = self.program.getReferenceManager()

        return [
            SymbolInfo(
                name=symbol.getName(),
                address=str(symbol.getAddress()),
                type=str(symbol.getSymbolType()),
                namespace=str(symbol.getParentNamespace()),
                source=str(symbol.getSource()),
                refcount=len(list(rm.getReferencesTo(symbol.getAddress()))),
                external=symbol.isExternal(),
            )
            for func in paginated_functions
            for symbol in [func.getSymbol()]
        ]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        if limit <= 0:
            return []

        pattern = re.compile(query, re.IGNORECASE) if query else None
        exports = []
        matches_seen = 0

        for symbol in self._get_export_symbols():
            if pattern and not pattern.search(symbol.getName()):
                continue
            if matches_seen < offset:
                matches_seen += 1
                continue
            exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
            matches_seen += 1
            if len(exports) >= limit:
                break

        return exports

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        if limit <= 0:
            return []

        pattern = re.compile(query, re.IGNORECASE) if query else None
        imports = []
        matches_seen = 0

        for symbol in self._get_import_symbols():
            if pattern and not pattern.search(symbol.getName()):
                continue
            if matches_seen < offset:
                matches_seen += 1
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
            matches_seen += 1
            if len(imports) >= limit:
                break

        return imports

    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
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

    def _get_literal_match_ids(self, query: str) -> typing.Any:
        assert self.program_info.code_collection is not None
        return self.program_info.code_collection.get(
            where_document={"$contains": query},
            include=[],
        )

    def _get_literal_result_page(self, query: str, limit: int, offset: int) -> typing.Any:
        assert self.program_info.code_collection is not None
        return self.program_info.code_collection.get(
            where_document={"$contains": query},
            limit=limit,
            offset=offset,
        )

    def _search_code_literal(
        self,
        literal_results: typing.Any,
        include_full_code: bool,
        preview_length: int,
    ) -> list[CodeSearchResult]:
        search_results: list[CodeSearchResult] = []
        if literal_results and literal_results.get("documents"):
            docs = literal_results["documents"] or []
            metadatas = literal_results.get("metadatas") or []

            for i, doc in enumerate(docs):
                metadata = metadatas[i] if i < len(metadatas) else {}
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
                        similarity=1.0,
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
                "Code indexing is not complete for this binary. Wait for "
                "list_project_binaries() to show code_collection=true, then retry search_code."
            )

        literal_id_results = self._get_literal_match_ids(query)
        literal_total = (
            len(literal_id_results["ids"])
            if literal_id_results and literal_id_results.get("ids")
            else 0
        )
        total_functions = self._get_code_collection_count()
        semantic_total = total_functions

        if search_mode == SearchMode.LITERAL:
            literal_page = self._get_literal_result_page(query, limit, offset)
            search_results = self._search_code_literal(
                literal_page,
                include_full_code,
                preview_length,
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
        """Searches for strings within a binary."""

        if not self.program_info.strings_collection:
            raise ValueError(
                "String indexing is not complete for this binary. Wait for "
                "list_project_binaries() to show strings_collection=true, then retry "
                "search_strings."
            )

        search_results = []
        results = self.program_info.strings_collection.get(
            where_document={"$contains": query}, limit=limit
        )
        remaining_limit = limit
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                metadata = results["metadatas"][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1,
                    )
                )
            remaining_limit -= len(results["documents"])

        if remaining_limit <= 0:
            return search_results

        results = self.program_info.strings_collection.query(
            query_texts=[query], n_results=remaining_limit
        )
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                metadata = results["metadatas"][0][i]  # type: ignore
                distance = results["distances"][0][i]  # type: ignore
                search_results.append(
                    StringSearchResult(
                        value=doc,
                        address=str(metadata["address"]),
                        similarity=1 - distance,
                    )
                )

        return search_results

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
