"""
Comprehensive tool implementations for pyghidra-mcp.
"""

import functools
import re
import typing

from ghidrecomp.callgraph import gen_callgraph
from jpype import JByte
from loguru import logger

from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfo,
    DecompiledFunction,
    ExportInfo,
    ImportInfo,
    StringInfo,
    StringSearchResult,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo


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
    """Comprehensive tool handler for Ghidra MCP tools with thread-safe access"""

    def __init__(self, program_info: "ProgramInfo"):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self._lock = program_info._lock

    @property
    def program(self):
        """Get the current program object (may be updated after save operations)"""
        return self.program_info.program

    @property
    def decompiler(self):
        """Get the current decompiler object (may be updated after save operations)"""
        return self.program_info.decompiler

    def _get_filename(self, func: "Function") -> str:
        """Generate unique identifier for decompilation caching.

        Creates a filename-safe identifier from function name and entry point.
        Truncates long function names to 50 characters to keep identifiers manageable.

        Args:
            func: Ghidra Function object

        Returns:
            str: Unique identifier in format "name-address"
        """
        max_path_len = 50
        return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"

    @handle_exceptions
    def find_function(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> "Function":
        """
        Resolve a function by name or address.
        - If name_or_address is an address, return the function at that entry point.
        - If it's a name, return exact match if unique.
        - If multiple exact matches, raise with suggestions (signature + entry point).
        - If none, raise with 'Did you mean...' suggestions from partial matches.
        """
        af = self.program.getAddressFactory()
        fm = self.program.getFunctionManager()

        # Try interpreting as an address
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return func
        except Exception:
            pass  # Not an address, continue with name search

        # Name-based search
        functions = self.get_all_functions(include_externals=include_externals)
        exact_matches = [
            f for f in functions if name_or_address.lower() == f.getSymbol().getName(True).lower()
        ]

        if len(exact_matches) == 1:
            return exact_matches[0]
        elif len(exact_matches) > 1:
            suggestions = [
                f"{f.getSymbol().getName(True)}({f.getSignature()}) @ {f.getEntryPoint()}"
                for f in exact_matches
            ]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )

        # No exact matches → suggest partials
        partial_matches = [
            f for f in functions if name_or_address.lower() in f.getSymbol().getName(True).lower()
        ]
        if partial_matches:
            suggestions = [
                f"{f.getSymbol().getName(True)} @ {f.getEntryPoint()}" for f in partial_matches
            ]
            raise ValueError(
                f"Function '{name_or_address}' not found. Did you mean one of these: "
                + ", ".join(suggestions)
            )

        raise ValueError(f"Function or symbol '{name_or_address}' not found.")

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
        Resolve a single symbol by name or address.
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, exact=True, partial=True)

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
        """Finds and decompiles a function in the currently loaded program and returns its pseudo-C code."""

        func = self.find_function(name_or_address)
        return self.decompile_function(func)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in the currently loaded program and returns its pseudo-C code."""
        from ghidra.util.task import ConsoleTaskMonitor

        with self._lock:  # Thread-safe decompilation
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
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """
        Gets all functions in the currently loaded program.
        Returns a python list that doesn't need to be re-initialized
        """
        with self._lock:  # Thread-safe function listing
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
        with self._lock:
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
        """Get all defined strings from the program.

        Handles Ghidra version differences:
        - Ghidra 11.3.2+: Uses getDefinedStrings() (includes strings from data types)
        - Ghidra 11.x: Uses getStrings() (classic string listing)

        Returns:
            List of StringInfo objects with string content and location
        """
        with self._lock:  # Thread-safe string listing
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

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name."""

        if not query:
            raise ValueError("Query string is required")

        symbols_info = []
        symbols = self.find_symbols(query)
        rm = self.program.getReferenceManager()

        # Search for symbols containing the query string
        for symbol in symbols:
            if query.lower() in symbol.getName(True).lower():
                ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
                symbols_info.append(
                    SymbolInfo(
                        name=symbol.name,
                        address=str(symbol.getAddress()),
                        type=str(symbol.getSymbolType()),
                        namespace=str(symbol.getParentNamespace()),
                        source=str(symbol.getSource()),
                        refcount=ref_count,
                        external=symbol.isExternal(),
                    )
                )
        return symbols_info[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from the currently loaded program."""
        with self._lock:  # Thread-safe export listing
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
        """Lists all imported functions and symbols from the currently loaded program."""
        with self._lock:
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
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address in the currently loaded program.
        """
        with self._lock:  # Thread-safe cross-reference listing
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
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary by direct filtering."""
        if not query:
            raise ValueError("Query string is required")

        all_strings = self.get_all_strings()
        query_lower = query.lower()

        # Filter strings that contain the query (case-insensitive)
        filtered_strings = [
            s for s in all_strings
            if query_lower in s.value.lower()
        ][:limit]

        return [
            StringSearchResult(
                value=s.value,
                address=s.address,
                similarity=1.0  # Exact match
            )
            for s in filtered_strings
        ]

    @handle_exceptions
    def get_image_base(self) -> str:
        """Get the image base address of the loaded program."""
        min_addr = self.program.getMinAddress()
        if min_addr is None:
            raise ValueError("Unable to determine image base - program has no address ranges")
        return str(min_addr)

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        with self._lock:
            max_read_size = 8192

            if size <= 0:
                raise ValueError("size must be > 0")

            if size > max_read_size:
                raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

            af = self.program.getAddressFactory()

            try:
                addr_str = address
                if address.lower().startswith("0x"):
                    addr_str = address[2:]

                addr = af.getAddress(addr_str)
                if addr is None:
                    raise ValueError(f"Invalid address: {address}")
            except Exception as e:
                raise ValueError(f"Invalid address format '{address}': {e}") from e

            mem = self.program.getMemory()
            if not mem.contains(addr):
                raise ValueError(f"Address {address} is not in mapped memory")

            # Use JPype to handle byte arrays properly for PyGhidra
            # Create Java byte array - JPype's runtime magic confuses static type checkers
            buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
            n = mem.getBytes(addr, buf)

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
        """Generate a call graph visualization for a function.

        Creates MermaidJS call graph showing caller/callee relationships.
        Supports multiple display types and condensation for large graphs.

        Args:
            function_name_or_address: Function name or entry point address
            cg_direction: CALLING (outgoing/callees) or CALLED (incoming/callers)
            cg_display_type: FLOW, FLOW_ENDS, or MIND visualization style
            include_refs: Include cross-reference information in nodes
            max_depth: Maximum graph depth (None for unlimited)
            max_run_time: Maximum generation time in seconds (default: 60)
            condense_threshold: Nodes threshold for condensation (default: 50)
            top_layers: Number of top layers to preserve when condensing
            bottom_layers: Number of bottom layers to preserve when condensing

        Returns:
            CallGraphResult with MermaidJS markdown and rendered image URL

        Raises:
            ValueError: If function not found
            TimeoutError: If graph generation exceeds max_run_time
        """
        with self._lock:
            cg_func = self.find_function(function_name_or_address)
            mermaid_url: str = ""

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
